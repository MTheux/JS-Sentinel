#!/usr/bin/env python3
"""
JS-Sentinel - Enhanced JavaScript Security Analyzer
Motor Híbrido: AST (Contextual) + Regex (Padrões)
"""

import re
import math
import requests
import jsbeautifier
import esprima
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, asdict
from datetime import datetime
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


@dataclass
class AnalysisResult:
    """Structure for analysis results"""
    url: str
    api_keys: List[Dict[str, Any]]
    credentials: List[Dict[str, Any]]
    emails: List[Dict[str, Any]]
    interesting_comments: List[Dict[str, Any]]
    xss_vulnerabilities: List[Dict[str, Any]]
    xss_functions: List[Dict[str, Any]]
    api_endpoints: List[Dict[str, Any]]
    parameters: List[Dict[str, Any]]
    paths_directories: List[Dict[str, Any]]
    high_entropy_strings: List[Dict[str, Any]]
    source_map_detected: bool
    source_map_url: str
    errors: List[str]
    file_size: int
    analysis_timestamp: str
    analysis_engine: str  # 'AST' ou 'Regex'


class ASTVisitor:
    """Classe auxiliar para navegar na árvore sintática do JavaScript"""
    def __init__(self):
        self.findings = {
            'credentials': [],
            'xss': [],
            'frameworks': set()
        }
        self.sensitive_vars = {'password', 'passwd', 'pwd', 'secret', 'token', 'apikey', 'auth'}
        self.sinks = {'eval', 'setTimeout', 'setInterval', 'execScript'}
        self.dom_sinks = {'innerHTML', 'outerHTML', 'document.write', 'document.writeln'}

    def visit(self, node):
        """Visita recursiva aos nós"""
        method_name = 'visit_' + node.type
        visitor = getattr(self, method_name, self.generic_visit)
        return visitor(node)

    def generic_visit(self, node):
        """Navega pelos filhos do nó atual"""
        for key, value in node.__dict__.items():
            if isinstance(value, list):
                for item in value:
                    if hasattr(item, 'type'):
                        self.visit(item)
            elif hasattr(value, 'type'):
                self.visit(value)

    def visit_VariableDeclarator(self, node):
        """
        Analisa declarações: const password = "123";
        AST detecta contexto: só alerta se for uma atribuição de string literal a variável sensível.
        """
        if node.id.type == 'Identifier' and node.init:
            var_name = node.id.name.lower()
            
            # Verifica credenciais hardcoded
            if any(s in var_name for s in self.sensitive_vars):
                if node.init.type == 'Literal' and isinstance(node.init.value, str):
                    if len(node.init.value) > 3: # Ignora strings muito curtas
                        self.findings['credentials'].append({
                            'type': 'Hardcoded Credential (AST)',
                            'match': f'{node.id.name} = "{node.init.value[:20]}..."',
                            'line': node.loc.start.line if hasattr(node, 'loc') else 0,
                            'severity': 'critical',
                            'confidence': 'High'
                        })
        self.generic_visit(node)

    def visit_AssignmentExpression(self, node):
        """
        Analisa atribuições: element.innerHTML = userInput;
        """
        # Detecção de XSS via DOM (innerHTML, outerHTML)
        if node.left.type == 'MemberExpression' and node.left.property.type == 'Identifier':
            prop_name = node.left.property.name
            if prop_name in self.dom_sinks:
                # Taint Analysis Simplificada: Verifica se o lado direito NÃO é uma string literal segura
                is_safe = (node.right.type == 'Literal')
                if not is_safe:
                    self.findings['xss'].append({
                        'type': f'DOM XSS Sink ({prop_name})',
                        'match': f'Assignment to {prop_name} with dynamic content',
                        'line': node.loc.start.line if hasattr(node, 'loc') else 0,
                        'severity': 'high'
                    })
        self.generic_visit(node)

    def visit_CallExpression(self, node):
        """
        Analisa chamadas de função: eval(code), React.createElement(...)
        """
        # 1. Sinks de Execução (eval, etc)
        if node.callee.type == 'Identifier':
            func_name = node.callee.name
            if func_name in self.sinks:
                # Verifica se argumento não é seguro (não é literal)
                if node.arguments and node.arguments[0].type != 'Literal':
                    self.findings['xss'].append({
                        'type': f'Execution Sink ({func_name})',
                        'match': f'Call to {func_name} with dynamic argument',
                        'line': node.loc.start.line if hasattr(node, 'loc') else 0,
                        'severity': 'critical'
                    })
            
            # Detecção de Frameworks
            if 'vue' in func_name.lower(): self.findings['frameworks'].add('Vue.js')
            if 'angular' in func_name.lower(): self.findings['frameworks'].add('Angular')

        # 2. React: dangerouslySetInnerHTML
        # Estrutura AST comum: { dangerouslySetInnerHTML: { __html: ... } } em ObjectExpression
        # Mas aqui olhamos chamadas, para React.createElement costuma ser detectado via MemberExpression
        if node.callee.type == 'MemberExpression':
             # React.createElement
             if hasattr(node.callee.object, 'name') and node.callee.object.name == 'React':
                 self.findings['frameworks'].add('React')
        
        self.generic_visit(node)

    def visit_Property(self, node):
        """Analisa propriedades de objetos, vital para React"""
        if node.key.type == 'Identifier' and node.key.name == 'dangerouslySetInnerHTML':
            self.findings['xss'].append({
                'type': 'React Dangerous Sink',
                'match': 'dangerouslySetInnerHTML usage detected',
                'line': node.loc.start.line if hasattr(node, 'loc') else 0,
                'severity': 'high'
            })
            self.findings['frameworks'].add('React')
        self.generic_visit(node)


class JavaScriptAnalyzer:
    """Analisador Híbrido: AST + Regex"""
    
    def __init__(self):
        self.beautifier_opts = jsbeautifier.default_options()
        self.beautifier_opts.indent_size = 2
        
        # --- PADRÕES REGEX (Mantidos para endpoints, comentários e fallbacks) ---
        self.api_key_patterns = [
            (r'AKIA[0-9A-Z]{16}', 'AWS Access Key ID', True),
            (r'(?i)(aws[_-]?secret[_-]?access[_-]?key|aws[_-]?secret)\s*[:=]\s*["\']([a-zA-Z0-9/+=]{40})["\']', 'AWS Secret Key', True),
            (r'AIza[0-9A-Za-z\-]{35}', 'Google API Key', True),
            (r'ghp_[a-zA-Z0-9]{36}', 'GitHub Personal Access Token', True),
            (r'sk_live_[a-zA-Z0-9]{24,}', 'Stripe Live Secret Key', True),
            (r'(?i)(api[_-]?key|apikey)\s*[:=]\s*["\']([a-zA-Z0-9_\-]{32,})["\']', 'Generic API Key', False),
            (r'\beyJ[A-Za-z0-9-_=]+\.eyJ[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]{10,}\b', 'JWT Token', False),
        ]
        
        self.email_patterns = [
            (r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b', 'Email Address', True),
        ]
        
        self.comment_patterns = [
            (r'//\s*(TODO|FIXME|XXX|HACK|BUG|SECURITY|WARNING)', 'Interesting Comment', True),
            (r'//\s*(password|secret|key|token|admin|backdoor)', 'Suspicious Comment', False),
        ]
        
        # Mantemos Regex de XSS como fallback caso o AST falhe ou o código seja muito fragmentado
        self.xss_patterns_fallback = [
            (r'\.innerHTML\s*=\s*([^;]+)', 'innerHTML Assignment (Regex)', 'high'),
            (r'document\.write\s*\(([^)]+)\)', 'document.write() (Regex)', 'high'),
            (r'eval\s*\([^)]*(\$|location|window\.|document\.|user)', 'eval() with User Input (Regex)', 'critical'),
        ]
        
        self.api_patterns = [
            (r'fetch\s*\(\s*["\']([^"\']+)["\']', 'fetch()'),
            (r'axios\.(get|post|put|delete)\s*\(\s*["\']([^"\']+)["\']', 'axios'),
            (r'["\'](/api/[^"\']+)["\']', 'API Path'),
            (r'baseURL\s*[:=]\s*["\']([^"\']+)["\']', 'Base URL'),
        ]
        
        self.path_patterns = [
            (r'["\'](/[a-zA-Z0-9_\-/]+)["\']', 'Path'),
            (r'["\'](\.\.?/[a-zA-Z0-9_\-/]+)["\']', 'Relative Path'),
        ]
        self.parameter_patterns = [
            (r'[?&](\w+)\s*=\s*([^&\s"\']+)', 'Query Parameter'),
        ]

    def calculate_shannon_entropy(self, data: str) -> float:
        if not data: return 0
        entropy = 0
        for x in range(256):
            p_x = float(data.count(chr(x))) / len(data)
            if p_x > 0: entropy += - p_x * math.log(p_x, 2)
        return entropy

    def detect_source_map(self, content: str, url: str) -> tuple:
        match = re.search(r'//# sourceMappingURL=([^\s]+)', content)
        if match:
            map_url = match.group(1)
            if not map_url.startswith('http') and 'http' in url:
                base_url = url.rsplit('/', 1)[0]
                map_url = f"{base_url}/{map_url}"
            return True, map_url
        return False, ""

    def find_high_entropy_strings(self, content: str, threshold=4.5) -> List[Dict[str, Any]]:
        findings = []
        # Regex ainda é o melhor para achar strings aleatórias soltas no código
        string_pattern = r'["\']([a-zA-Z0-9_\-\/\+\=]{20,})["\']'
        matches = re.finditer(string_pattern, content)
        seen = set()
        
        for match in matches:
            potential_secret = match.group(1)
            if potential_secret in seen: continue
            if any(x in potential_secret.lower() for x in ['application/', 'text/', 'http', 'www', 'function', 'return', 'error']): continue
            
            entropy = self.calculate_shannon_entropy(potential_secret)
            if entropy > threshold:
                seen.add(potential_secret)
                line_num = content[:match.start()].count('\n') + 1
                findings.append({
                    'type': 'High Entropy String',
                    'match': potential_secret[:50] + '...',
                    'entropy': round(entropy, 2),
                    'line': line_num,
                    'line_content': content.split('\n')[line_num-1].strip()[:100],
                    'severity': 'high'
                })
        return findings

    def fetch_js_file(self, url: str) -> Optional[str]:
        try:
            if '0.0.0.0' in url: url = url.replace('0.0.0.0', 'localhost')
            headers = {'User-Agent': 'Mozilla/5.0 (JS-Sentinel Security Scanner)'}
            response = requests.get(url, headers=headers, timeout=30, verify=False)
            return response.text if response.status_code == 200 else None
        except Exception:
            return None

    def find_patterns(self, content: str, patterns: List[tuple], context_lines: int = 2) -> List[Dict[str, Any]]:
        """Método legado de Regex para padrões que não dependem de AST"""
        findings = []
        lines = content.split('\n')
        for pattern_info in patterns:
            pattern = pattern_info[0]
            label = pattern_info[1]
            severity = pattern_info[2] if len(pattern_info) > 2 else 'info'
            
            try:
                for match in re.finditer(pattern, content, re.MULTILINE | re.IGNORECASE):
                    line_num = content[:match.start()].count('\n') + 1
                    line_content = lines[line_num - 1].strip() if line_num <= len(lines) else ""
                    
                    findings.append({
                        'type': label,
                        'match': match.group(0)[:150],
                        'line': line_num,
                        'line_content': line_content,
                        'context': '\n'.join(lines[max(0, line_num-2):min(len(lines), line_num+1)]),
                        'severity': severity
                    })
            except Exception: continue
        return findings

    def _generic_extract(self, content, patterns, type_label):
        return self.find_patterns(content, patterns)

    def analyze_ast(self, content: str) -> Dict[str, List]:
        """Executa a análise AST usando Esprima"""
        visitor = ASTVisitor()
        try:
            # Tenta parsear como Script. Se falhar, tenta Module (ES6)
            try:
                tree = esprima.parseScript(content, {'loc': True, 'tolerant': True})
            except Exception:
                tree = esprima.parseModule(content, {'loc': True, 'tolerant': True})
            
            visitor.visit(tree)
            return visitor.findings
        except Exception as e:
            # Se falhar o parse (ex: JSX complexo, sintaxe inválida), retorna vazio e usa fallback
            return None

    def analyze(self, url: str, content: str = None) -> AnalysisResult:
        errors = []
        if content is None:
            content = self.fetch_js_file(url)
            if content is None:
                return self._empty_result(url, ["Failed to fetch URL"])

        file_size = len(content)
        has_source_map, source_map_url = self.detect_source_map(content, url)
        
        # Beautify se necessário (ajuda tanto o Regex quanto o AST em arquivos minificados)
        if len(content.split('\n')) < 5 and len(content) > 1000:
            try: content = jsbeautifier.beautify(content, self.beautifier_opts)
            except: pass

        # --- FASE 1: ANÁLISE AST (Avançada) ---
        ast_findings = self.analyze_ast(content)
        used_engine = 'AST + Regex' if ast_findings else 'Regex Only'
        
        credentials = []
        xss_vulns = []
        
        if ast_findings:
            credentials.extend(ast_findings['credentials'])
            xss_vulns.extend(ast_findings['xss'])
            # Se o AST funcionou bem, confiamos nele para XSS e Credenciais
            # Framework detection via AST
            if ast_findings['frameworks']:
                for fw in ast_findings['frameworks']:
                    xss_vulns.append({
                        'type': 'Framework Detected',
                        'match': f'{fw} structure identified',
                        'line': 1,
                        'severity': 'info'
                    })
        
        # --- FASE 2: ANÁLISE REGEX (Complementar/Fallback) ---
        
        # Sempre rodamos Regex para API Keys (pois chaves são strings, não lógica)
        api_keys = self.find_patterns(content, self.api_key_patterns)
        
        # Rodamos Regex para emails, comentários e entropia (sempre úteis)
        emails = self.find_patterns(content, self.email_patterns)
        comments = self.find_patterns(content, self.comment_patterns)
        high_entropy = self.find_high_entropy_strings(content)
        
        # Se o AST falhou ou não achou nada, usamos o Regex de XSS como fallback
        if not ast_findings or (not xss_vulns and not credentials):
            xss_vulns.extend(self.find_patterns(content, self.xss_patterns_fallback))
        
        # Regex é melhor para achar URLs/Endpoints soltos em strings
        api_endpoints = self._generic_extract(content, self.api_patterns, 'API Endpoint')
        parameters = self._generic_extract(content, self.parameter_patterns, 'Parameter')
        paths = self._generic_extract(content, self.path_patterns, 'Path')

        return AnalysisResult(
            url=url,
            api_keys=api_keys,
            credentials=credentials,
            emails=emails,
            interesting_comments=comments,
            xss_vulnerabilities=xss_vulns,
            xss_functions=[], # AST já cobre funções perigosas dentro de 'xss_vulnerabilities'
            api_endpoints=api_endpoints,
            parameters=parameters,
            paths_directories=paths,
            high_entropy_strings=high_entropy,
            source_map_detected=has_source_map,
            source_map_url=source_map_url,
            errors=errors,
            file_size=file_size,
            analysis_timestamp=datetime.now().isoformat(),
            analysis_engine=used_engine
        )

    def _empty_result(self, url, errors):
        return AnalysisResult(
            url=url, api_keys=[], credentials=[], emails=[], interesting_comments=[],
            xss_vulnerabilities=[], xss_functions=[], api_endpoints=[], parameters=[],
            paths_directories=[], high_entropy_strings=[], source_map_detected=False,
            source_map_url="", errors=errors, file_size=0,
            analysis_timestamp=datetime.now().isoformat(), analysis_engine="None"
        )