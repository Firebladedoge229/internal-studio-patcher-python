import argparse
import os
import time
import winreg
from pathlib import Path
from stagescan import start

def patch(input_path: Path, output_path: Path):
    with open(input_path, 'rb') as f:
        input_data = f.read()
    start(input_data, output_path)

def get_default_icon_path():
    reg_key = winreg.OpenKey(winreg.HKEY_CLASSES_ROOT, r"roblox-studio\DefaultIcon")
    icon_path, _ = winreg.QueryValueEx(reg_key, "")
    return icon_path

def main():
    parser = argparse.ArgumentParser(description="Patch Roblox Studio executable.")
    parser.add_argument('--input', type=Path, help="Input file path")
    parser.add_argument('--output', type=Path, help="Output file path")
    args = parser.parse_args()

    input_path = args.input if args.input else Path(get_default_icon_path())
    
    if args.output:
        output_path = args.output
    else:
        if __debug__:
            output_path = input_path.with_name("RobloxStudioBeta_INTERNAL.exe")
        else:
            output_path = input_path # TODO: Is convenience really worth it?

    start_time = time.time()

    patch(input_path, output_path)

    elapsed_time = time.time() - start_time
    print(f"Patched in {elapsed_time:.2f} seconds.")

if __name__ == '__main__':
    main()
