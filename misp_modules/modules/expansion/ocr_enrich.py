import json
import binascii
import cv2
import np
import pytesseract

misperrors = {'error': 'Error'}
mispattributes = {'input': ['attachment'],
                  'output': ['freetext']}
moduleinfo = {'version': '0.2', 'author': 'Sascha Rommelfangen',
              'description': 'OCR decoder',
              'module-type': ['expansion']}

moduleconfig = []


def filter_decoded(decoded):
    for line in decoded.split('\n'):
        if decoded_line := line.strip('\t\x0b\x0c\r '):
            yield decoded_line


def handler(q=False):
    if q is False:
        return False
    q = json.loads(q)
    filename = q['attachment']
    try:
        img_array = np.frombuffer(binascii.a2b_base64(q['data']), np.uint8)
    except Exception as e:
        print(e)
        err = "Couldn't fetch attachment (JSON 'data' is empty). Are you using the 'Query enrichment' action?"
        misperrors['error'] = err
        print(err)
        return misperrors

    image = img_array
    image = cv2.imdecode(img_array, cv2.IMREAD_COLOR)
    try:
        decoded = pytesseract.image_to_string(cv2.cvtColor(image, cv2.COLOR_BGR2RGB))
        return {
            'results': [
                {
                    'types': ['freetext'],
                    'values': list(filter_decoded(decoded)),
                    'comment': f"OCR from file {filename}"
                }
            ]
        }
    except Exception as e:
        print(e)
        err = "Couldn't analyze file type. Only images are supported right now."
        misperrors['error'] = err
        return misperrors


def introspection():
    return mispattributes


def version():
    moduleinfo['config'] = moduleconfig
    return moduleinfo
