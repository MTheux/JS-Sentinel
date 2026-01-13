#!/usr/bin/env python3
"""
JS-Sentinel Web Application
Backend Flask
Desenvolvido por: mftheux
"""

from flask import Flask, render_template, request, jsonify, send_from_directory
from flask_cors import CORS
from analyzer import JavaScriptAnalyzer
import json
import uuid
import os
from typing import List, Dict
import sys

# Aumenta o limite de recursão para parsers AST complexos em arquivos grandes
sys.setrecursionlimit(3000)

app = Flask(__name__)
CORS(app)

# Get the base directory
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

analyzer = JavaScriptAnalyzer()

# Armazena resultados em memória (em produção, usar Redis/DB)
analysis_results = {}


@app.route('/')
def index():
    """Main page"""
    return render_template('index.html')


@app.route('/api/analyze', methods=['POST'])
def analyze():
    """
    Endpoint principal para análise de arquivos JavaScript
    Suporta: URL única, Múltiplas URLs e Upload de Arquivo
    """
    try:
        urls = []
        is_direct_upload = False
        direct_filename = ""
        direct_content = ""

        if request.is_json:
            data = request.get_json()
            if not data:
                return jsonify({'error': 'JSON inválido no corpo da requisição'}), 400
            
            urls = data.get('urls', [])
            if isinstance(urls, str):
                urls = [urls]
            
            if not urls:
                url = data.get('url', '').strip()
                if url:
                    urls = [url]
            
            if not urls:
                return jsonify({'error': 'URL(s) são obrigatórias'}), 400
        else:
            # Handle file upload
            if 'file' in request.files:
                file = request.files['file']
                if file.filename:
                    filename_lower = file.filename.lower()
                    # Lê o conteúdo ignorando erros de decodificação
                    content = file.read().decode('utf-8', errors='ignore')
                    
                    # CASO 1: Upload direto de arquivo JS/Code
                    if any(filename_lower.endswith(ext) for ext in ['.js', '.json', '.html', '.htm', '.txt']):
                        # Verifica se é uma lista de URLs ou código fonte
                        lines = content.split('\n')
                        is_url_list = False
                        
                        # Heurística simples: se as primeiras linhas parecem URLs, é lista
                        valid_urls = [l.strip() for l in lines[:5] if l.strip().startswith(('http://', 'https://'))]
                        if len(valid_urls) > 0 and len(lines) < 1000: # Lista de URLs
                            is_url_list = True
                        elif filename_lower.endswith('.js'): # Arquivo JS código
                            is_url_list = False
                        
                        if is_url_list:
                            urls = [line.strip() for line in lines if line.strip() and not line.strip().startswith('#')]
                        else:
                            is_direct_upload = True
                            direct_filename = file.filename
                            direct_content = content
                    
                    # CASO 2: Arquivo JSON estruturado
                    elif filename_lower.endswith('.json'):
                        try:
                            json_data = json.loads(content)
                            if isinstance(json_data, list):
                                urls = [str(u).strip() for u in json_data]
                            elif isinstance(json_data, dict) and 'urls' in json_data:
                                urls = [str(u).strip() for u in json_data['urls']]
                        except json.JSONDecodeError:
                            # Se falhar JSON, tenta tratar como texto puro (upload direto)
                            is_direct_upload = True
                            direct_filename = file.filename
                            direct_content = content
                else:
                    return jsonify({'error': 'Nenhum arquivo enviado'}), 400
            else:
                return jsonify({'error': 'Nenhum arquivo ou dados fornecidos'}), 400
        
        # Gera ID da sessão
        session_id = str(uuid.uuid4())
        total_files = 1 if is_direct_upload else len(urls)
        
        analysis_results[session_id] = {
            'files': [],
            'total': total_files,
            'completed': 0
        }
        
        results = []
        
        # Função auxiliar para formatar o objeto de resultado
        def format_result(file_id, res_obj):
            return {
                'file_id': file_id,
                'url': res_obj.url,
                'api_keys': res_obj.api_keys or [],
                'credentials': res_obj.credentials or [],
                'emails': res_obj.emails or [],
                'interesting_comments': res_obj.interesting_comments or [],
                'xss_vulnerabilities': res_obj.xss_vulnerabilities or [],
                'xss_functions': res_obj.xss_functions or [],
                'api_endpoints': res_obj.api_endpoints or [],
                'parameters': res_obj.parameters or [],
                'paths_directories': res_obj.paths_directories or [],
                'high_entropy_strings': getattr(res_obj, 'high_entropy_strings', []),
                'source_map_detected': getattr(res_obj, 'source_map_detected', False),
                'source_map_url': getattr(res_obj, 'source_map_url', ""),
                'analysis_engine': getattr(res_obj, 'analysis_engine', 'Regex Only'),
                'errors': res_obj.errors or [],
                'file_size': res_obj.file_size,
                'analysis_timestamp': res_obj.analysis_timestamp,
            }

        # Se for upload direto, analisa o conteúdo
        if is_direct_upload:
            try:
                # Chama o analyzer passando o CONTEÚDO diretamente
                # O analyzer agora usa AST se possível
                result = analyzer.analyze(f"Upload: {direct_filename}", content=direct_content)
                result_dict = format_result(1, result)
                
                results.append(result_dict)
                analysis_results[session_id]['files'].append(result_dict)
                analysis_results[session_id]['completed'] = 1
            except Exception as e:
                import traceback
                traceback.print_exc()
                return jsonify({'error': f'Falha na análise do arquivo: {str(e)}'}), 500

        else:
            # Processamento de lista de URLs
            for idx, url in enumerate(urls):
                url = url.strip()
                if not url:
                    continue
                
                try:
                    # O analyzer faz o fetch e decide entre AST/Regex
                    result = analyzer.analyze(url)
                    result_dict = format_result(idx + 1, result)
                    
                    results.append(result_dict)
                    analysis_results[session_id]['files'].append(result_dict)
                    analysis_results[session_id]['completed'] += 1
                except Exception as e:
                    import traceback
                    traceback.print_exc()
                    error_result = {
                        'file_id': idx + 1,
                        'url': url,
                        'errors': [f'Falha crítica na análise: {str(e)}'],
                        'api_keys': [], 'credentials': [], 'emails': [],
                        'interesting_comments': [], 'xss_vulnerabilities': [],
                        'xss_functions': [], 'api_endpoints': [], 'parameters': [],
                        'paths_directories': [], 'high_entropy_strings': [],
                        'source_map_detected': False, 'source_map_url': "",
                        'analysis_engine': 'Failed',
                        'file_size': 0, 'analysis_timestamp': '',
                    }
                    results.append(error_result)
                    analysis_results[session_id]['files'].append(error_result)
                    analysis_results[session_id]['completed'] += 1
        
        return jsonify({
            'session_id': session_id,
            'total_files': len(results),
            'results': results
        })
    
    except Exception as e:
        import traceback
        error_msg = str(e)
        traceback.print_exc()
        return jsonify({'error': error_msg}), 500


@app.route('/api/results/<session_id>', methods=['GET'])
def get_results(session_id):
    """Get analysis results for a session"""
    if session_id not in analysis_results:
        return jsonify({'error': 'Sessão não encontrada'}), 404
    
    session_data = analysis_results[session_id]
    return jsonify(session_data)


@app.route('/api/file/<session_id>/<int:file_id>', methods=['GET'])
def get_file_result(session_id, file_id):
    """Get specific file result"""
    if session_id not in analysis_results:
        return jsonify({'error': 'Sessão não encontrada'}), 404
    
    files = analysis_results[session_id]['files']
    file_result = next((f for f in files if f.get('file_id') == file_id), None)
    
    if not file_result:
        return jsonify({'error': 'Arquivo não encontrado'}), 404
    
    return jsonify(file_result)


@app.route('/<path:filename>')
def serve_file(filename):
    """Serve arquivos estáticos para teste local"""
    if filename.startswith('api/') or filename.startswith('static/') or filename.startswith('templates/'):
        return jsonify({'error': 'Not found'}), 404
    if filename.endswith('.js'):
        try:
            return send_from_directory(BASE_DIR, filename, mimetype='application/javascript')
        except FileNotFoundError:
            return jsonify({'error': f'Arquivo {filename} não encontrado'}), 404
    return jsonify({'error': 'Arquivo não encontrado'}), 404


if __name__ == '__main__':
    # Em produção, debug deve ser False
    app.run(debug=True, host='0.0.0.0', port=5000)