import plistlib
from os import path, makedirs
from typing import (
    Optional,
    Tuple,
)

plist_filepath = '/Applications/HomeKit Accessory Simulator.app/' \
                 'Contents/Frameworks/HAPAccessoryKit.framework/Resources/default.metadata.plist'

current_directory = path.dirname(path.realpath(__file__))
characteristics_directory = path.realpath(path.join(current_directory, '..', 'pyhap', 'characteristics'))
template_filepath = 'templates/characteristic.py.template'

characteristic_formats = {
    'string': 'string',
    'bool': 'bool',
    'uint8': 'int',
    'uint16': 'int',
    'uint32': 'int',
    'int32': 'int',
    'float': 'float',
    'tlv8': 'tlv',
}


def main():
    makedirs(characteristics_directory, exist_ok=True)

    plist = get_plist()

    characteristic_init = ''
    characteristic_init_filepath = path.join(characteristics_directory, '__init__.py')

    for characteristic in plist['Characteristics']:
        underscore_name, class_name = generate_characteristic(characteristic)
        if underscore_name and class_name:
            characteristic_init += f'from pyhap.characteristics.{underscore_name} import {class_name}\n'

    with open(characteristic_init_filepath, 'w+') as f:
        f.write(characteristic_init)


def generate_characteristic(characteristic: dict) -> Tuple[Optional[str], Optional[str]]:
    characteristic_format = characteristic_formats.get(characteristic['Format'])

    if not characteristic_format:
        print('Unknown characteristic format:', characteristic['Format'])
        return None, None

    template = open(template_filepath).read()

    class_name = gen_class_name(characteristic['Name'])
    dot_name = gen_dot_name(characteristic['Name'])
    permissions = gen_permissions(characteristic['Properties'])

    template = template.format(
        class_name=class_name,
        dot_name=dot_name,
        uuid=characteristic['UUID'],
        format=characteristic_format,
        permissions=permissions
    )

    underscore_name = gen_underscore_name(characteristic['Name'])
    characteristic_filepath = path.join(characteristics_directory, underscore_name + '.py')

    with open(characteristic_filepath, 'w+') as f:
        f.write(template)

    return underscore_name, class_name


def gen_class_name(name: str) -> str:
    return name.replace(' ', '')


def gen_dot_name(name: str) -> str:
    return name.replace(' ', '.').lower()


def gen_underscore_name(name: str) -> str:
    return name.replace(' ', '_').lower()


def gen_permissions(permissions: list) -> str:
    permission_types = {
        'read': 'CharacteristicPermission.pair_read',
        'write': 'CharacteristicPermission.pair_write',
        'cnotify': 'CharacteristicPermission.notify',
    }
    converted_permissions = []

    for permission in permissions:
        if permission not in permission_types:
            print('Unknown permission:', permission)
            continue

        converted_permissions.append(f'{permission_types[permission]},\n')

    spaces = ' ' * 12

    return spaces.join(converted_permissions)


def get_plist() -> dict:
    with open(plist_filepath, 'rb') as f:
        return plistlib.load(f)


if __name__ == '__main__':
    main()
