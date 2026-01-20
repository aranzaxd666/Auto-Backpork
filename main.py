#!/usr/bin/env python3

import os
import sys
import shutil
import argparse
from pathlib import Path
from typing import Dict, List, Tuple, Optional
from src.ps5_sdk_version_patcher import SDKVersionPatcher
from src.make_fself import FakeSignedELFConverter

# ANSI color codes
GREEN = '\033[92m'
YELLOW = '\033[93m'
RED = '\033[91m'
CYAN = '\033[96m'
BLUE = '\033[94m'
RESET = '\033[0m'
BOLD = '\033[1m'

def print_banner():
    """Print a banner for the tool."""
    banner = f"""
{CYAN}{BOLD}╔══════════════════════════════════════════════════════════╗
║         PS5 ELF Downgrade & Fake Sign Tool           ║
║      SDK Version Patcher + Fake Signed Converter      ║
╚══════════════════════════════════════════════════════════╝{RESET}
"""
    print(banner)

def get_sdk_version_choice() -> int:
    """Prompt user to select an SDK version pair."""
    pairs = SDKVersionPatcher.get_supported_pairs()
    
    print(f"{CYAN}Available SDK Version Pairs:{RESET}")
    print(f"{YELLOW}{'─' * 60}{RESET}")
    print(f"{BOLD}{'Pair':<6} {'PS5 SDK Version':<20} {'PS4 Version':<20}{RESET}")
    print(f"{YELLOW}{'─' * 60}{RESET}")
    
    for pair_num, (ps5_ver, ps4_ver) in pairs.items():
        print(f"  {pair_num:<4} 0x{ps5_ver:08X}{' ' * 10}0x{ps4_ver:08X}")
    
    print(f"{YELLOW}{'─' * 60}{RESET}")
    
    while True:
        try:
            choice = input(f"\n{CYAN}Enter SDK version pair number (1-{len(pairs)}): {RESET}").strip()
            if not choice:
                print(f"{YELLOW}Using default: Pair 4 (0x04000031, 0x09040001){RESET}")
                return 4
            
            choice_num = int(choice)
            if choice_num in pairs:
                return choice_num
            else:
                print(f"{RED}Invalid choice. Please select a number between 1 and {len(pairs)}.{RESET}")
        except ValueError:
            print(f"{RED}Invalid input. Please enter a number.{RESET}")

def get_paid_choice() -> int:
    """Prompt user to select PAID (Program Authentication ID)."""
    paid_options = {
        1: ("Fake Paid (Default)", 0x3100000000000002),
        2: ("System Paid", 0x3200000000000001),
        3: ("NPDRM Paid", 0x3300000000000003),
        4: ("Custom Paid", None)
    }
    
    print(f"\n{CYAN}Available PAID (Program Authentication ID) Options:{RESET}")
    print(f"{YELLOW}{'─' * 60}{RESET}")
    print(f"{BOLD}{'Option':<8} {'Description':<30} {'Value':<20}{RESET}")
    print(f"{YELLOW}{'─' * 60}{RESET}")
    
    for option_num, (desc, value) in paid_options.items():
        if value:
            print(f"  {option_num:<6} {desc:<30} 0x{value:016X}")
        else:
            print(f"  {option_num:<6} {desc:<30} (custom input)")
    
    print(f"{YELLOW}{'─' * 60}{RESET}")
    
    while True:
        try:
            choice = input(f"\n{CYAN}Select PAID option (1-4, default=1): {RESET}").strip()
            if not choice:
                print(f"{YELLOW}Using default: Fake Paid (0x3100000000000002){RESET}")
                return paid_options[1][1]
            
            choice_num = int(choice)
            if choice_num in paid_options:
                if choice_num == 4:
                    while True:
                        try:
                            custom_paid = input(f"{CYAN}Enter custom PAID (hex, e.g., 0x3200000000000001): {RESET}").strip()
                            if custom_paid.startswith('0x'):
                                custom_paid = int(custom_paid, 16)
                            else:
                                custom_paid = int(custom_paid, 0)
                            
                            if 0 <= custom_paid <= 0xFFFFFFFFFFFFFFFF:
                                return custom_paid
                            else:
                                print(f"{RED}PAID must be a 64-bit value (0-0xFFFFFFFFFFFFFFFF){RESET}")
                        except ValueError:
                            print(f"{RED}Invalid hex value. Try again.{RESET}")
                else:
                    return paid_options[choice_num][1]
            else:
                print(f"{RED}Invalid choice. Please select 1-4.{RESET}")
        except ValueError:
            print(f"{RED}Invalid input. Please enter a number.{RESET}")

def get_ptype_choice() -> int:
    """Prompt user to select program type."""
    ptype_options = {
        1: ("Fake (Default)", 1),  # FakeSignedELFConverter.parse_ptype('fake') returns 1
        2: ("NPDRM Executable", 4),  # FakeSignedELFConverter.parse_ptype('npdrm_exec')
        3: ("NPDRM Dynamic Library", 5),  # FakeSignedELFConverter.parse_ptype('npdrm_dynlib')
        4: ("System Executable", 8),  # FakeSignedELFConverter.parse_ptype('system_exec')
        5: ("System Dynamic Library", 9),  # FakeSignedELFConverter.parse_ptype('system_dynlib')
        6: ("Custom PType", None)
    }
    
    print(f"\n{CYAN}Available Program Type Options:{RESET}")
    print(f"{YELLOW}{'─' * 60}{RESET}")
    print(f"{BOLD}{'Option':<8} {'Description':<30} {'Value':<20}{RESET}")
    print(f"{YELLOW}{'─' * 60}{RESET}")
    
    for option_num, (desc, value) in ptype_options.items():
        if value is not None:
            print(f"  {option_num:<6} {desc:<30} 0x{value:08X}")
        else:
            print(f"  {option_num:<6} {desc:<30} (custom input)")
    
    print(f"{YELLOW}{'─' * 60}{RESET}")
    
    while True:
        try:
            choice = input(f"\n{CYAN}Select program type (1-6, default=1): {RESET}").strip()
            if not choice:
                print(f"{YELLOW}Using default: Fake (0x1){RESET}")
                return ptype_options[1][1]
            
            choice_num = int(choice)
            if choice_num in ptype_options:
                if choice_num == 6:
                    while True:
                        try:
                            custom_ptype = input(f"{CYAN}Enter custom PType (hex or name): {RESET}").strip()
                            # Try to parse as hex first
                            try:
                                if custom_ptype.startswith('0x'):
                                    ptype_value = int(custom_ptype, 16)
                                else:
                                    ptype_value = int(custom_ptype, 0)
                            except ValueError:
                                # Try to parse as string
                                try:
                                    ptype_value = FakeSignedELFConverter.parse_ptype(custom_ptype.lower())
                                except Exception:
                                    raise ValueError(f"Unknown program type: {custom_ptype}")
                            
                            if 0 <= ptype_value <= 0xFFFFFFFF:
                                return ptype_value
                            else:
                                print(f"{RED}PType must be a 32-bit value (0-0xFFFFFFFF){RESET}")
                        except Exception as e:
                            print(f"{RED}{str(e)}. Try again or use 'fake', 'npdrm_exec', etc.{RESET}")
                else:
                    return ptype_options[choice_num][1]
            else:
                print(f"{RED}Invalid choice. Please select 1-6.{RESET}")
        except ValueError:
            print(f"{RED}Invalid input. Please enter a number.{RESET}")

def copy_fakelib(source_dir: Path, output_dir: Path) -> Tuple[bool, str]:
    """
    Copy the fakelib directory to the output directory.
    
    Args:
        source_dir: Root project directory containing fakelib
        output_dir: Output directory where fakelib should be copied
        
    Returns:
        Tuple of (success, message)
    """
    fakelib_source = source_dir / "fakelib"
    
    if not fakelib_source.exists():
        return True, f"fakelib directory not found at {fakelib_source} (skipping)"
    
    if not fakelib_source.is_dir():
        return False, f"fakelib path exists but is not a directory: {fakelib_source}"
    
    fakelib_dest = output_dir / "fakelib"
    
    try:
        # Remove existing fakelib in output if it exists
        if fakelib_dest.exists():
            shutil.rmtree(fakelib_dest)
        
        # Copy fakelib directory
        shutil.copytree(fakelib_source, fakelib_dest)
        
        # Count files for reporting
        file_count = sum(1 for _ in fakelib_dest.rglob('*') if _.is_file())
        return True, f"Copied fakelib directory ({file_count} files)"
    
    except Exception as e:
        return False, f"Failed to copy fakelib: {str(e)}"

def is_elf_file(file_path: Path) -> bool:
    """
    Check if a file is an ELF file by checking its magic bytes.
    
    Args:
        file_path: Path to the file to check
        
    Returns:
        True if it's an ELF file
    """
    # Skip .bak backup files
    if file_path.name.endswith('.bak'):
        return False
    
    try:
        with open(file_path, 'rb') as f:
            magic = f.read(4)
            return magic == b'\x7FELF'  # ELF magic
    except:
        return False

def process_files(input_dir: Path, output_dir: Path, sdk_pair: int, 
                  paid: int, ptype: int, create_backup: bool = True,
                  use_colors: bool = True) -> Dict[str, Dict[str, any]]:
    """
    Main processing function that orchestrates the workflow.
    
    Args:
        input_dir: Directory containing decrypted files
        output_dir: Directory for output files
        sdk_pair: SDK version pair number
        paid: Program Authentication ID
        ptype: Program type
        create_backup: Whether to create backups during downgrade
        use_colors: Whether to use colored output
        
    Returns:
        Dictionary with processing results
    """
    results = {
        'downgrade': {'successful': 0, 'failed': 0, 'files': {}},
        'signing': {'successful': 0, 'failed': 0, 'files': {}},
        'fakelib': {'success': False, 'message': ''}
    }
    
    print(f"\n{BLUE}{BOLD}[Step 1/3] Downgrading SDK Versions{RESET}")
    print(f"{YELLOW}{'─' * 60}{RESET}")
    
    # Step 1: Downgrade SDK versions
    sdk_patcher = SDKVersionPatcher(
        create_backup=create_backup,
        use_colors=use_colors
    )
    sdk_patcher.set_versions_by_pair(sdk_pair)
    
    ps5_ver, ps4_ver = sdk_patcher.get_current_versions()
    print(f"{CYAN}Using PS5 SDK: 0x{ps5_ver:08X}, PS4 Version: 0x{ps4_ver:08X}{RESET}")
    
    # Find all ELF files in input directory, skipping .bak files
    elf_files = []
    for root, dirs, files in os.walk(input_dir):
        for filename in files:
            file_path = Path(root) / filename
            
            # Skip .bak backup files
            if filename.endswith('.bak'):
                continue
            
            if is_elf_file(file_path):
                elf_files.append(file_path)
    
    if not elf_files:
        print(f"{YELLOW}No ELF files found in input directory (excluding .bak files){RESET}")
        return results
    
    print(f"Found {len(elf_files)} ELF file(s) to process (skipped .bak backup files)\n")
    
    for elf_file in elf_files:
        relative_path = elf_file.relative_to(input_dir)
        print(f"  Processing: {relative_path}")
        
        try:
            success, message = sdk_patcher.patch_file(str(elf_file))
            
            results['downgrade']['files'][str(elf_file)] = {
                'success': success,
                'message': message
            }
            
            if success:
                results['downgrade']['successful'] += 1
                print(f"    {GREEN}✓ Success{RESET}")
            else:
                results['downgrade']['failed'] += 1
                print(f"    {RED}✗ {message}{RESET}")
        except Exception as e:
            results['downgrade']['failed'] += 1
            error_msg = f"Error: {str(e)}"
            results['downgrade']['files'][str(elf_file)] = {
                'success': False,
                'message': error_msg
            }
            print(f"    {RED}✗ {error_msg}{RESET}")
    
    print(f"\n{CYAN}Downgrade complete: {results['downgrade']['successful']} successful, "
          f"{results['downgrade']['failed']} failed{RESET}")
    
    # Step 2: Fake sign the downgraded files
    print(f"\n{BLUE}{BOLD}[Step 2/3] Fake Signing Files{RESET}")
    print(f"{YELLOW}{'─' * 60}{RESET}")
    
    # Create output directory structure
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Initialize converter
    converter = FakeSignedELFConverter(
        paid=paid,
        ptype=ptype,
        app_version=0,
        fw_version=0,
        auth_info=None
    )
    
    print(f"{CYAN}Using PAID: 0x{paid:016X}, PType: 0x{ptype:08X}{RESET}\n")
    
    for elf_file in elf_files:
        relative_path = elf_file.relative_to(input_dir)
        input_file_str = str(elf_file)
        
        # Skip if downgrade failed
        if not results['downgrade']['files'].get(input_file_str, {}).get('success', False):
            print(f"  Skipping (downgrade failed): {relative_path}")
            results['signing']['files'][str(elf_file)] = {
                'success': False,
                'output': '',
                'message': 'Skipped due to downgrade failure'
            }
            results['signing']['failed'] += 1
            continue
        
        # Output file keeps same name and extension
        output_file = output_dir / relative_path
        
        # Create parent directories if they don't exist
        output_file.parent.mkdir(parents=True, exist_ok=True)
        
        print(f"  Signing: {relative_path}")
        
        # Sign the file
        try:
            success = converter.sign_file(input_file_str, str(output_file))
            
            results['signing']['files'][str(elf_file)] = {
                'success': success,
                'output': str(output_file),
                'message': 'Success' if success else 'Failed'
            }
            
            if success:
                results['signing']['successful'] += 1
                print(f"    {GREEN}✓ Success{RESET}")
            else:
                results['signing']['failed'] += 1
                print(f"    {RED}✗ Failed{RESET}")
        except Exception as e:
            results['signing']['failed'] += 1
            error_msg = f"Error: {str(e)}"
            results['signing']['files'][str(elf_file)] = {
                'success': False,
                'output': str(output_file),
                'message': error_msg
            }
            print(f"    {RED}✗ {error_msg}{RESET}")
    
    print(f"\n{CYAN}Signing complete: {results['signing']['successful']} successful, "
          f"{results['signing']['failed']} failed{RESET}")
    
    # Step 3: Copy fakelib directory
    print(f"\n{BLUE}{BOLD}[Step 3/3] Copying Fakelib Directory{RESET}")
    print(f"{YELLOW}{'─' * 60}{RESET}")
    
    # Find project root
    project_root = Path(__file__).parent
    success, message = copy_fakelib(project_root, output_dir)
    
    results['fakelib']['success'] = success
    results['fakelib']['message'] = message
    
    if success:
        print(f"{GREEN}✓ {message}{RESET}")
    else:
        print(f"{YELLOW}⚠ {message}{RESET}")
    
    return results

def print_summary(results: Dict[str, Dict[str, any]], output_dir: Path):
    """Print a summary of the processing results."""
    print(f"\n{BLUE}{BOLD}══════════════════════════════════════════════════════════{RESET}")
    print(f"{CYAN}{BOLD}                      PROCESSING SUMMARY                     {RESET}")
    print(f"{BLUE}{BOLD}══════════════════════════════════════════════════════════{RESET}")
    
    downgrade = results['downgrade']
    signing = results['signing']
    fakelib = results['fakelib']
    
    print(f"\n{BOLD}Downgrade Results:{RESET}")
    print(f"  {GREEN}Successful: {downgrade['successful']}{RESET}")
    print(f"  {RED if downgrade['failed'] > 0 else YELLOW}Failed: {downgrade['failed']}{RESET}")
    print(f"  {CYAN}Total: {downgrade['successful'] + downgrade['failed']}{RESET}")
    
    print(f"\n{BOLD}Signing Results:{RESET}")
    print(f"  {GREEN}Successful: {signing['successful']}{RESET}")
    print(f"  {RED if signing['failed'] > 0 else YELLOW}Failed: {signing['failed']}{RESET}")
    print(f"  {CYAN}Total: {signing['successful'] + signing['failed']}{RESET}")
    
    print(f"\n{BOLD}Fakelib Copy:{RESET}")
    if fakelib['success']:
        print(f"  {GREEN}✓ {fakelib['message']}{RESET}")
    else:
        print(f"  {YELLOW}⚠ {fakelib['message']}{RESET}")
    
    # List failed files if any
    failed_downgrade = [f for f, data in downgrade['files'].items() if not data.get('success', False)]
    failed_signing = [f for f, data in signing['files'].items() if not data.get('success', False)]
    
    if failed_downgrade:
        print(f"\n{BOLD}Failed Downgrade Files:{RESET}")
        for f in failed_downgrade[:5]:  # Show only first 5
            filename = Path(f).name
            msg = downgrade['files'][f].get('message', 'Unknown error')
            print(f"  {RED}• {filename}: {msg[:100]}{'...' if len(msg) > 100 else ''}{RESET}")
        if len(failed_downgrade) > 5:
            print(f"  {YELLOW}... and {len(failed_downgrade) - 5} more{RESET}")
    
    if failed_signing:
        print(f"\n{BOLD}Failed Signing Files:{RESET}")
        for f in failed_signing[:5]:  # Show only first 5
            filename = Path(f).name
            msg = signing['files'][f].get('message', 'Unknown error')
            print(f"  {RED}• {filename}: {msg[:100]}{'...' if len(msg) > 100 else ''}{RESET}")
        if len(failed_signing) > 5:
            print(f"  {YELLOW}... and {len(failed_signing) - 5} more{RESET}")
    
    print(f"\n{BLUE}{BOLD}══════════════════════════════════════════════════════════{RESET}")
    print(f"{GREEN}{BOLD}Processing complete! Output directory: {output_dir}{RESET}")
    print(f"{BLUE}{BOLD}══════════════════════════════════════════════════════════{RESET}")

def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='PS5 ELF Downgrade & Fake Sign Tool - Processes decrypted ELF files'
    )
    
    parser.add_argument(
        '--input', '-i',
        type=str,
        help='Input directory containing decrypted ELF files'
    )
    
    parser.add_argument(
        '--output', '-o',
        type=str,
        help='Output directory for processed files'
    )
    
    parser.add_argument(
        '--sdk-pair', '-s',
        type=int,
        help='SDK version pair number (1-10)'
    )
    
    parser.add_argument(
        '--paid',
        type=str,
        help='Program Authentication ID (hex, e.g., 0x3100000000000002)'
    )
    
    parser.add_argument(
        '--ptype',
        type=str,
        help='Program type (name or hex, e.g., "fake" or "0x1")'
    )
    
    parser.add_argument(
        '--no-backup',
        action='store_true',
        help='Do not create backup files during downgrade'
    )
    
    parser.add_argument(
        '--no-colors',
        action='store_true',
        help='Disable colored output'
    )
    
    parser.add_argument(
        '--batch',
        action='store_true',
        help='Run in batch mode without interactive prompts'
    )
    
    args = parser.parse_args()
    
    # Print banner
    print_banner()
    
    # Get input directory
    if args.input:
        input_dir = Path(args.input)
    elif args.batch:
        print(f"{RED}Error: Input directory required in batch mode{RESET}")
        sys.exit(1)
    else:
        input_path = input(f"{CYAN}Enter input directory (decrypted files): {RESET}").strip()
        if not input_path:
            print(f"{RED}Error: Input directory is required{RESET}")
            sys.exit(1)
        input_dir = Path(input_path)
    
    # Validate input directory
    if not input_dir.exists():
        print(f"{RED}Error: Input directory does not exist: {input_dir}{RESET}")
        sys.exit(1)
    
    if not input_dir.is_dir():
        print(f"{RED}Error: Input path is not a directory: {input_dir}{RESET}")
        sys.exit(1)
    
    # Get output directory
    if args.output:
        output_dir = Path(args.output)
    elif args.batch:
        print(f"{RED}Error: Output directory required in batch mode{RESET}")
        sys.exit(1)
    else:
        output_path = input(f"{CYAN}Enter output directory: {RESET}").strip()
        if not output_path:
            print(f"{RED}Error: Output directory is required{RESET}")
            sys.exit(1)
        output_dir = Path(output_path)
    
    # Create output directory if it doesn't exist
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Get SDK version pair
    sdk_pairs = SDKVersionPatcher.get_supported_pairs()
    
    if args.sdk_pair:
        sdk_pair = args.sdk_pair
        if sdk_pair not in sdk_pairs:
            print(f"{RED}Error: Invalid SDK pair. Must be between 1 and {len(sdk_pairs)}{RESET}")
            sys.exit(1)
    elif args.batch:
        sdk_pair = 4  # Default in batch mode
    else:
        sdk_pair = get_sdk_version_choice()
    
    # Get PAID
    if args.paid:
        try:
            if args.paid.startswith('0x'):
                paid = int(args.paid, 16)
            else:
                paid = int(args.paid, 0)
            
            if not (0 <= paid <= 0xFFFFFFFFFFFFFFFF):
                print(f"{RED}Error: PAID must be a 64-bit value (0-0xFFFFFFFFFFFFFFFF){RESET}")
                sys.exit(1)
        except ValueError:
            print(f"{RED}Error: Invalid PAID format. Use hex (0x...) or decimal{RESET}")
            sys.exit(1)
    elif args.batch:
        paid = 0x3100000000000002  # Default in batch mode
    else:
        paid = get_paid_choice()
    
    # Get PType
    if args.ptype:
        try:
            if args.ptype.startswith('0x'):
                ptype = int(args.ptype, 16)
            else:
                try:
                    ptype = int(args.ptype, 0)
                except ValueError:
                    ptype = FakeSignedELFConverter.parse_ptype(args.ptype.lower())
            
            if not (0 <= ptype <= 0xFFFFFFFF):
                print(f"{RED}Error: PType must be a 32-bit value (0-0xFFFFFFFF){RESET}")
                sys.exit(1)
        except Exception as e:
            print(f"{RED}Error: Invalid ptype '{args.ptype}': {str(e)}{RESET}")
            print(f"Valid options: fake, npdrm_exec, npdrm_dynlib, system_exec, system_dynlib, host_kernel, secure_module, secure_kernel")
            sys.exit(1)
    elif args.batch:
        ptype = 1  # Default in batch mode
    else:
        ptype = get_ptype_choice()
    
    # Get SDK version pair values
    ps5_sdk_version, ps4_version = sdk_pairs[sdk_pair]
    
    # Print configuration
    print(f"\n{BLUE}{BOLD}══════════════════════════════════════════════════════════{RESET}")
    print(f"{CYAN}{BOLD}                      CONFIGURATION                         {RESET}")
    print(f"{BLUE}{BOLD}══════════════════════════════════════════════════════════{RESET}")
    print(f"  {BOLD}Input Directory:{RESET} {input_dir}")
    print(f"  {BOLD}Output Directory:{RESET} {output_dir}")
    print(f"  {BOLD}SDK Version Pair:{RESET} {sdk_pair} (PS5: 0x{ps5_sdk_version:08X}, PS4: 0x{ps4_version:08X})")
    print(f"  {BOLD}PAID:{RESET} 0x{paid:016X}")
    print(f"  {BOLD}PType:{RESET} 0x{ptype:08X}")
    print(f"  {BOLD}Create Backup:{RESET} {'Yes' if not args.no_backup else 'No'}")
    print(f"{BLUE}{BOLD}══════════════════════════════════════════════════════════{RESET}")
    
    # Confirm before proceeding
    if not args.batch:
        confirm = input(f"\n{CYAN}Proceed with processing? (y/N): {RESET}").strip().lower()
        if confirm not in ['y', 'yes']:
            print(f"{YELLOW}Processing cancelled.{RESET}")
            sys.exit(0)
    
    # Process files
    try:
        results = process_files(
            input_dir=input_dir,
            output_dir=output_dir,
            sdk_pair=sdk_pair,
            paid=paid,
            ptype=ptype,
            create_backup=not args.no_backup,
            use_colors=not args.no_colors
        )
        
        # Print summary
        print_summary(results, output_dir)
        
        # Exit with appropriate code
        if results['downgrade']['failed'] > 0 or results['signing']['failed'] > 0:
            print(f"\n{YELLOW}Warning: Some files failed to process{RESET}")
            sys.exit(1)
        else:
            print(f"\n{GREEN}All files processed successfully!{RESET}")
            sys.exit(0)
            
    except KeyboardInterrupt:
        print(f"\n{YELLOW}Processing interrupted by user.{RESET}")
        sys.exit(1)
    except Exception as e:
        print(f"\n{RED}Unexpected error: {str(e)}{RESET}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()