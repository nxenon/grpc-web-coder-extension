"""
GRPC-Analyze
Extracting Methods, Services and Messages (Routes) in JS files (grpc-web)
"""

import re
from texttable import Texttable
import os
import sys
import traceback

_this_dir = os.path.dirname(os.path.abspath(__file__))
_project_root = os.path.dirname(_this_dir)
_libs_path = os.path.join(_project_root, 'libs')

if _libs_path not in sys.path:
    sys.path.insert(0, _libs_path)

print('DEBUG: attempting import jsbeautifier from', _libs_path)

try:
    from jsbeautifier import beautify
    print('DEBUG: jsbeautifier imported successfully (Jython).')
except Exception as e:
    print('ERROR: failed to import jsbeautifier:')
    traceback.print_exc()
    beautify = None


def create_table(columns_list, rows_list):
    table = Texttable()

    table_list = [columns_list]
    for i in rows_list:
        table_list.append(i)
    table.add_rows(table_list)
    table_string = table.draw()
    # indented_table_string = '    ' + table_string.replace('\n', '\n    ')  # Add space before each line

    return table_string


def beautify_js_content(content):
    try:
        beautified = beautify(content)

    except Exception as e:
        print('An error occurred in beautifying Javascript code: ' + str(e))
        raise e

    return beautified


def extract_endpoints(content):
    pattern = r'MethodDescriptor\("(\/.*?)"'
    compiled_pattern = re.compile(pattern)
    matched_items = compiled_pattern.findall(content)
    matched_items = list(matched_items)
    print('Found Endpoints:')
    if matched_items:
        for m in matched_items:
            print("  " + m)

    print("")


def extract_messages(content):
    pattern = r'proto\.(.*)\.prototype\.set(.*).*=.*function\(.*\).*{\s*.*set(.*)\(.*?,(.*?),'
    compiled_pattern = re.compile(pattern)
    matched_items = compiled_pattern.findall(content)
    matched_items = list(matched_items)

    message_list = {}

    print('Found Messages:')
    if matched_items:
        for m in matched_items:

            if m[0].strip() not in message_list:
                message_list[m[0]] = []
            if m[1].strip() not in message_list[m[0].strip()]:
                # add proto field *name* 1, add proto field *type* 2, add proto field *number* 3
                temp_list = [m[1].strip(), m[2].strip(), m[3].strip()]
                message_list[m[0]].append(temp_list)

        for m2 in message_list.keys():
            print("")
            print('%s:' % m2)
            print(create_table(columns_list=['Field Name', 'Field Type', 'Field Number'], rows_list=message_list[m2]))

    print("")


def extract_all_grpc_messages_and_endpoints(content):
    beautified = beautify_js_content(content)

    extract_endpoints(beautified)
    extract_messages(beautified)
