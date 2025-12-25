import os
import logging
from flask import request, jsonify
from PIL import Image
from pathlib import Path
import base64


def create_safe_preview(filepath, max_dimension=800, quality=85):

    try:

        img = Image.open(filepath)
        original_size = img.size
        img.thumbnail((max_dimension, max_dimension), Image.Resampling.LANCZOS)

        if img.mode != 'RGB':
            img = img.convert('RGB')

        with io.BytesIO() as buffer:
            if img.format == 'PNG':
                img.save(buffer, format='PNG',optimize=True)
                mime_type = 'image/png'
            else:
                img.save(buffer, format='JPEG', quality=quality, optimize=True)
                mime_type = 'image/jpeg'
            img_size_now = img.size
            buffer.seek(0)
            compressed_data = buffer.getvalue()
            buffer.seek(0)

            base64_str = base64.b64encode(compressed_data).decode('utf-8')

            return {
                'url': f'data:{mime_type};base64,{base64_str}',
                'filepath': filepath,
                'original_size': original_size,
                'size_now':img_size_now
            }

    except Exception as e:
        logging.error(f'\ncreate_safe_preview error:\n{e}')
        return{'success': False, 'message': 'error'}







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
    #u can change the path if u want
    if request.method == 'POST':
        try:
            file = request.files.get('file')
            if file and file.filename:
                if not file.content_length or file.content_length < 100 * 1024 or file.content_length > 10 * 1024 * 1024:
                    return jsonify({'success': False, 'message': 'file size error'})

                if (file.filename.count('.') > 1 or
                        file.filename.count('\\') > 0 or
                        not file.filename.strip().lower().endswith(
                        ('.jpg', '.jpeg', '.bmp', '.png', '.gif', '.webp'))):
                    return jsonify({'success': False, 'message': 'invalid filename'})

                if not is_valid_image(file):
                    return jsonify({'success': False, 'message': 'invalid file format'})
                filepath = os.path.join(UPLOAD_FOLDER, file.filename)
                abs_upload_folder = Path(UPLOAD_FOLDER).resolve()
                abs_filepath = Path(filepath).resolve()
                if not abs_filepath.is_relative_to(abs_upload_folder):
                    return jsonify({'success': False, 'message': 'path error'})
                if os.path.exists(filepath):
                    return jsonify({'success': False, 'message': 'file already exists'})

                os.makedirs(UPLOAD_FOLDER,exist_ok=True)
                file.save(filepath)
                result = create_safe_preview(filepath=abs_filepath)


                return jsonify({'success': True, 'message': result})
            return jsonify({'success': False, 'message': 'file not found'})
        except Exception as e:
            logging.error(f'\napi_add_file error:\n{e}')
            return jsonify({'success': False, 'message': 'system error'})

def api_file_remove(filename:str, UPLOAD_FOLDER='/uploads/'):
    try:
        if not filename:
            return jsonify({'success': False, 'message': 'filename can\'t let empty'})
        if (filename.count('.') > 1 or
                filename.count('\\') > 0 or
                not filename.strip().lower().endswith(
                    ('.png', '.jpg', '.jpeg', '.bmp', '.gif', '.webp'))):
            return jsonify({'success': False, 'message': 'invalid filename'})
        filepath = os.path.join(UPLOAD_FOLDER, filename)
        abs_filepath = Path(filepath).resolve()
        abs_upload_folder = Path(UPLOAD_FOLDER).resolve()
        if not os.path.exists(abs_filepath):
            return jsonify({'success': False, 'message': 'file not found'})
        if not abs_filepath.is_relative_to(abs_upload_folder):
            return jsonify({'success': False, 'message': 'path error'})
        os.remove(filepath)
        return jsonify({'success': True, 'message': f'remove successful:\n{str(abs_filepath)}'})
    except PermissionError:
        return jsonify({'success': False, 'message': 'system error'})
    except (ValueError, TypeError):
        return jsonify({'success': False, 'message': 'invalid file format'})
    except Exception as e:
        logging.error(f'\napi_file_remove error:\n{e}')
        return jsonify({'success': False, 'message': 'system error'})

def api_get_file_by_name(filename:str, UPLOAD_FOLDER='/uploads/'):
    try:
        if not filename:
            return jsonify({'success': False, 'message': 'filename can\'t let empty'})
        if filename.count('.') > 1 or filename.count('\\') > 0 or not filename.strip().lower().endswith(
                ('.jpg', '.jpeg', '.bmp', '.png', '.gif', '.webp')):
            return jsonify({'success': False, 'message': 'invalid filename'})
        path = os.path.join(UPLOAD_FOLDER, filename)
        if not os.path.exists(path):
            return jsonify({'success': False, 'message': 'file not found'})
        upload_abs = Path(UPLOAD_FOLDER).resolve()
        abs_file = Path(path).resolve()
        if not os.path.isfile(abs_file):
            return jsonify({
                'success': False,
                'message': 'not isfile'
            })

        if not abs_file.startswith(upload_abs):
            return jsonify({'success': False, 'message': 'path error'})

        result = create_safe_preview(filepath=abs_file)
        if result['success'] == True:
            return jsonify({'success':True,'message':result})
        else:
            return jsonify({'success':False,'message':result})

    except PermissionError:
        pass
    except (ValueError, TypeError):
        return jsonify({'success': False, 'message': 'invalid file format'})
    except Exception as e:
        logging.error(f'\napi_get_file_by_name error:\n{e}')
        return jsonify({'success': False, 'message': 'system error'})



def api_return_all_file(UPLOAD_FOLDER='/uploads/'):
    try:
        images = []
        for file in os.listdir(UPLOAD_FOLDER):
            if file.lower().endswith(('.jpg', '.jpeg', '.bmp', '.png', '.gif', '.webp')):
                filepath = Path(os.path.join(UPLOAD_FOLDER,file)).resolve()
                images.append(str(filepath))
        if images == []:
            return jsonify({'success': False, 'message': 'file not found'})
        return jsonify({'success': True, 'message': images})
    except PermissionError:
        pass
    except Exception as e:
        logging.error(f'\napi_return_file error:\n{e}')
        return jsonify({'success': False, 'message': 'system error'})

