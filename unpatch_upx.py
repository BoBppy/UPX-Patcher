import argparse
import sys

def find_pe_offset(data: bytearray) -> int:
    """Finds the offset of the PE signature 'PE\0\0'."""
    try:
        return data.find(b'PE\x00\x00')
    except ValueError:
        return -1

def get_machine_type(data: bytearray, pe_offset: int) -> int | None:
    """Reads the Machine field from the PE header."""
    machine_offset = pe_offset + 4  # PE signature is 4 bytes, Machine field is immediately after COFF File Header
    if machine_offset + 1 < len(data): # Ensure 2 bytes can be read
        # Machine field is 2 bytes, little-endian
        return int.from_bytes(data[machine_offset:machine_offset+2], byteorder='little')
    return None

def restore_section_names(data: bytearray, verbose: bool = False) -> bytearray:
    """Restores known UPX section names."""
    replacements = {
        b'.dosx': b'UPX0\x00',
        b'.fish': b'UPX1\x00',
        b'.code': b'UPX2\x00'
    }
    for old_name, new_name in replacements.items():
        count = data.count(old_name)
        if count > 0:
            data = data.replace(old_name, new_name)
            if verbose:
                print(f"Restored section name: Replaced '{old_name.decode(errors="ignore")}' with '{new_name.decode(errors="ignore")}' {count} time(s).")
    return data

def restore_dos_stub(data: bytearray, verbose: bool = False) -> bytearray:
    """Restores the standard DOS stub message."""
    patcher_url = b'https://github.com/DosX-dev/UPX-Patcher'
    original_dos_stub = b'This program cannot be run in DOS mode.'
    
    count = data.count(patcher_url)
    if count > 0:
        # The original UPX-Patcher replaces based on finding the original DOS stub.
        # We are reversing this by finding the URL and replacing it.
        # This assumes the URL string is unique enough.
        # Length difference handling: Python's replace will handle different lengths.
        data = data.replace(patcher_url, original_dos_stub)
        if verbose:
            print(f"Restored DOS stub: Replaced patcher URL with standard DOS stub {count} time(s).")
    return data

def restore_api_names(data: bytearray, verbose: bool = False) -> bytearray:
    """Restores 'ExitProcess' API name from 'CopyContext'."""
    # UPX-Patcher replaces "ExitProcess" with "CopyContext"
    # Both are 11 bytes long.
    modified_api = b'CopyContext'
    original_api = b'ExitProcess'
    
    count = data.count(modified_api)
    if count > 0:
        data = data.replace(modified_api, original_api)
        if verbose:
            print(f"Restored API name: Replaced '{modified_api.decode(errors="ignore")}' with '{original_api.decode(errors="ignore")}' {count} time(s).")
    return data

def restore_entry_point(data: bytearray, verbose: bool = False) -> bytearray:
    """Restores entry point modifications based on PE architecture."""
    pe_offset = find_pe_offset(data)
    if pe_offset == -1:
        if verbose:
            print("Warning: PE signature 'PE\0\0' not found. "
                  "Skipping entry point restoration.")
        return data

    machine_type = get_machine_type(data, pe_offset)
    if machine_type is None:
        if verbose:
            print("Warning: Could not determine Machine type from PE header. "
                  "Skipping entry point restoration.")
        return data

    if machine_type == 0x014c:  # IMAGE_FILE_MACHINE_I386 (32-bit)
        # UPX-Patcher: Search({&H0, &H60, &HBE}), ReplaceWith({&H0, &H55, &HBE})
        # Script to restore: Search({&H0, &H55, &HBE}), ReplaceWith({&H0, &H60, &HBE})
        search_bytes_i386 = b'\x00\x55\xBE'
        replace_bytes_i386 = b'\x00\x60\xBE'
        count = data.count(search_bytes_i386)
        if count > 0:
            data = data.replace(search_bytes_i386, replace_bytes_i386)
            if verbose:
                print(f"Restored 32-bit entry point: Replaced modified sequence {count} time(s).")
        elif verbose:
            print("No 32-bit modified entry point sequence found.")

    elif machine_type == 0x8664:  # IMAGE_FILE_MACHINE_AMD64 (64-bit)
        # UPX-Patcher: Search({&H53,&H57,&H56,&H55}), ReplaceWith({&H53,&H56,&H57,&H55})
        # Script to restore: Search({&H53,&H56,&H57,&H55}), ReplaceWith({&H53,&H57,&H56,&H55})
        search_bytes_x64 = b'\x53\x56\x57\x55'  # What UPX-Patcher wrote
        replace_bytes_x64 = b'\x53\x57\x56\x55'  # Original UPX bytes UPX-Patcher searched for

        count = data.count(search_bytes_x64)
        if count > 0:
            data = data.replace(search_bytes_x64, replace_bytes_x64)
            if verbose:
                print(f"Restored 64-bit entry point: Replaced modified sequence {count} time(s).")
        elif verbose:
            print("No 64-bit modified entry point sequence found.")
    else:
        if verbose:
            print(f"Warning: Unknown or unsupported Machine type (0x{machine_type:04x}). "
                  "Skipping entry point restoration for specific architecture.")
    return data

def main():
    parser = argparse.ArgumentParser(
        description="Reverses modifications made by UPX-Patcher.")
    parser.add_argument(
        "-i", "--input", required=True,
        help="Path to the input file (modified by UPX-Patcher).")
    parser.add_argument(
        "-o", "--output", required=True,
        help="Path to save the 'unpatched' output file.")
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Enable verbose output.")
    args = parser.parse_args()

    if args.verbose:
        print(f"Processing file: {args.input}")

    try:
        with open(args.input, 'rb') as f:
            file_data = bytearray(f.read())
    except FileNotFoundError:
        print(f"Error: Input file '{args.input}' not found.")
        sys.exit(1)
    except IOError as e:
        print(f"Error reading input file '{args.input}': {e}")
        sys.exit(1)

    # Apply restoration functions
    file_data = restore_section_names(file_data, args.verbose)
    file_data = restore_dos_stub(file_data, args.verbose)
    file_data = restore_api_names(file_data, args.verbose)
    file_data = restore_entry_point(file_data, args.verbose)
    # Version block is intentionally not handled as per plan (original bytes unknown)

    try:
        with open(args.output, 'wb') as f:
            f.write(file_data)
        if args.verbose:
            print(f"Successfully wrote 'unpatched' file to: {args.output}")
        else:
            print(f"Output file saved to: {args.output}")
            
    except IOError as e:
        print(f"Error writing output file '{args.output}': {e}")
        sys.exit(1)

if __name__ == "__main__":
    main() 