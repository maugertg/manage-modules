import os
import json

from requests.exceptions import HTTPError
from threatresponse import ThreatResponse

def get_module_type_configs(path='types'):
    module_type_files = []
    for (dirpath, dirnames, filenames) in os.walk(path):
        for file in filenames:
            file_path = os.path.join(dirpath, file)
            module_type_files.append(file_path)

    return module_type_files

def read_module_type_config(config_file):
    with open(config_file, 'r') as f:
        config = json.loads(f.read())

    return config

def post_module_type(client, payload):
    return client.int.module_type.post(payload)

def del_module_type(client, module_id):
    return client.int.module_type.delete(module_id)

def del_modules(client, module_output):
    for module_id, module_title in module_output.items():
        print(f'Deleting {module_title}', end='')
        response = del_module_type(client, module_id)
        if response.ok:
            print(' - DONE!')

def cleaup_modules(client):
    def update_file(ids):
        with open('module_ids.txt', 'w') as f:
            for _id in ids:
                f.write(f'{module_id}\n')

    with open('module_ids.txt') as f:
        ids = f.read().splitlines()
    ids_tracking = list(ids)    
    for module_id in ids:
        print(f'Deleting {module_id}', end='')
        try:
            response = del_module_type(client, module_id)
            if response.ok:
                ids_tracking.remove(module_id)
                update_file(ids_tracking)
                print(' - DONE!')
        except HTTPError:
            ids_tracking.remove(module_id)
            print(f' - does not exist')
        update_file(ids_tracking)

def save_module_id(module_id):
    with open('module_ids.txt', 'a') as f:
        f.write(f'{module_id}\n')

def main():
    client_id = ''
    client_password = ''

    client = ThreatResponse(
        client_id=client_id,
        client_password=client_password,
        region='us'
    )

    cleaup_modules(client)

    module_configs = get_module_type_configs()
    module_output = {}

    for module in module_configs:
        config = read_module_type_config(module)
        response = post_module_type(client, config)
        module_id = response['id']
        title = response['title']
        module_output.setdefault(module_id, title)
        save_module_id(module_id)

if __name__ == '__main__':
    main()
