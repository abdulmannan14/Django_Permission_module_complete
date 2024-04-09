import json
from . import permission as all_permissions

from rest_framework.renderers import JSONRenderer


def convert_serialized_data_to_json(data):
    json_string = JSONRenderer().render(data)
    json_string = json_string.decode('utf-8')
    json_string = json.loads(json_string)
    return json_string


def compare_and_update_permissions(data):
    try:
        all_permission = all_permissions.all_permissions
        for permission1 in data["permissions"]:
            for permission2 in all_permission:
                if permission1["module_name"] == permission2["module_name"]:
                    permission2.update(permission1)
                    break

        return all_permission
    except Exception as e:
        all_permission = all_permissions.all_permissions
        for permission1 in data:
            for permission2 in all_permission:
                if permission1["module_name"] == permission2["module_name"]:
                    permission2.update(permission1)
                    break
        return all_permission


def send_default_permissions():
    return all_permissions.all_permissions
