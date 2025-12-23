import os
import logging
from flask import request, jsonify
from PIL import Image



def is_valid_image(file):
    try:
        file.seek(0)
        img = Image.open(file)
        img.verify()
        file.seek(0)
        return True
    except:
        return False
def api_add_file(UPLOAD_FOLDER='/uploads/'):
    if request.method == 'POST':
        try:
            file = request.files.get('file')
            if file and file.filename:
                if not file.content_length or file.content_length < 100 * 1024 or file.content_length > 10 * 1024 * 1024:
                    return jsonify({'success': False, 'message': 'file size error'})

                if file.filename.count('.') > 1 or not file.filename.strip().lower().endswith(
                        ('.png', '.jpg', '.jpeg', '.gif', '.bmp')):
                    return jsonify({'success': False, 'message': 'invallid filename'})

                if not is_valid_image(file):
                    return jsonify({'success': False, 'message': 'invalid file format'})

                filepath = os.path.join(UPLOAD_FOLDER, file.filename)
                if os.path.exists(filepath):
                    return jsonify({'success': False, 'message': 'file already exists'})

                os.makedirs(UPLOAD_FOLDER,exist_ok=True)
                file.save(filepath)
                return jsonify({'success': True, 'message': 'file upload success'})
            return jsonify({'success': False, 'message': 'file not found'})
        except Exception as e:
            logging.error(f'\napi_add_file error:\n{e}')
            return jsonify({'success': False, 'message': 'system error'})
