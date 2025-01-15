import paramiko, os, re, json
from parse_projects_from_json import get_projects_for_platform, get_path_for_project
import shlex

# Define the directories
HF_VERSIONING_DIR = '/build/sy1653/HFVersioning'
QSSI_DIR = f'{HF_VERSIONING_DIR}/QSSI'
VENDOR_DIR = f'{HF_VERSIONING_DIR}/VENDOR'
COMMON_DIR = f'{HF_VERSIONING_DIR}/COMMON'

def generate_hf_versioning_patches(repo_init_command, build_fingerprint):

    platform_name = derive_platform_name(build_fingerprint)

    # Create an SSH client
    ssh = paramiko.SSHClient()
    pem_key_path = 'google_compute_engine.pem'
    sftp = None
    qssi_branch_name = None
    vendor_branch_name = None
    common_branch_name = None

    # Configure SSH client settings
    ssh.load_system_host_keys(os.path.expanduser('~/.ssh/known_hosts'))
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    # Read the private key file
    try:
        private_key = paramiko.RSAKey.from_private_key_file(pem_key_path)
    except paramiko.SSHException:
        private_key = paramiko.DSSKey.from_private_key_file(pem_key_path)

    try:
        # Establish SSH connection
        print("Establishing SSH connection!!!")
        #key = paramiko.PKey.from_private_key_file('google_compute_engine.ppk')
        # Connect to SSH server
        ssh.connect('10.132.4.37', username='sy1653', pkey=private_key)
        # Establish SFTP connection
        sftp = ssh.open_sftp()

        directories = [HF_VERSIONING_DIR, QSSI_DIR, VENDOR_DIR, COMMON_DIR]
        ensure_remote_directories_exists(ssh, directories)
        commands = extract_repo_init_commands(repo_init_command)
        print(commands)
        #exit()
        if commands['qssi'] is None and commands['vendor'] is None:
            execute_repo_init(ssh,COMMON_DIR,commands['legacy'])
            common_branch_name = get_branch_name_from_input(repo_init_command, "COMMON")
        else:
            execute_repo_init(ssh, QSSI_DIR, commands['qssi'])
            execute_repo_init(ssh, VENDOR_DIR, commands['vendor'])
            qssi_branch_name = get_branch_name_from_input(repo_init_command, "QSSI")
            vendor_branch_name = get_branch_name_from_input(repo_init_command, "VENDOR")
        
        # Sync QSSI projects
        qssi_projects = get_projects_for_platform(platform_name, 'QSSI')
        replacements = parse_build_fingerprint(build_fingerprint)
        input_file_path = 'target_files_changes_' +platform_name+'.json'  # Path to your input JSON file
        output_file_path = 'updated_target_files_changes_'+platform_name+'.json' #Path to output JSON file

        # Read the input JSON file
        input_json = read_json_file(input_file_path)
        parsed_result = parse_build_fingerprint(build_fingerprint)
        modified_json = update_json_with_parsed_values(input_json, parsed_result)
        
        #print("qssi_projects", qssi_projects)
        if qssi_projects:
            qssi_success = execute_repo_sync(ssh, QSSI_DIR, qssi_projects)
            for each_project in qssi_projects:
                qssi_projects_path = get_path_for_project(platform_name, 'QSSI', each_project)
                if qssi_projects_path.endswith("make"):
                    patch_file = update_build_repo_diff_file("build_repo_6490_t.patch", "updated_build_repo_6490_t.patch",replacements)
                    checkout_branch_via_ssh(ssh, f'{QSSI_DIR}/'+qssi_projects_path, qssi_branch_name)
                    apply_patch(ssh, sftp, f'{QSSI_DIR}/'+qssi_projects_path, patch_file)
                    push_changes_for_review(ssh, f'{QSSI_DIR}/'+qssi_projects_path, qssi_branch_name, commit_message="Retain Build Fingerprint 1/3", topic="AUTOMATED_HF_VERSIONING")
                elif qssi_projects_path.endswith("core"):
                    patch_file = update_build_repo_diff_file("system_core_6490_t.patch", "updated_system_core_6490_t.patch",replacements)
                    checkout_branch_via_ssh(ssh, f'{QSSI_DIR}/'+qssi_projects_path, qssi_branch_name)
                    apply_patch(ssh, sftp, f'{QSSI_DIR}/'+qssi_projects_path, patch_file)
                    push_changes_for_review(ssh, f'{QSSI_DIR}/'+qssi_projects_path, qssi_branch_name, commit_message="Retain Build Fingerprint 2/3", topic="AUTOMATED_HF_VERSIONING")
                else:
                    print(f"One or more apply patch commands for {each_project} failed.")
        else:
            qssi_success = True  # No QSSI projects to sync

        # Sync VENDOR projects
        vendor_projects = get_projects_for_platform(platform_name, 'VENDOR')
        if vendor_projects:
            vendor_success = execute_repo_sync(ssh, VENDOR_DIR, vendor_projects)
            write_json_to_file(modified_json, output_file_path)
            for each_project in vendor_projects:
                vendor_projects_path = get_path_for_project(platform_name, 'VENDOR', each_project)
                checkout_branch_via_ssh(ssh, f'{VENDOR_DIR}/'+vendor_projects_path, vendor_branch_name)
                update_files_on_server(ssh, sftp, f'{VENDOR_DIR}/'+vendor_projects_path, read_json_file(output_file_path))
                push_changes_for_review(ssh, f'{VENDOR_DIR}/'+vendor_projects_path, vendor_branch_name, commit_message="Retain Build Fingerprint 3/3", topic="AUTOMATED_HF_VERSIONING")
        else:
            vendor_success = True  # No VENDOR projects to sync

        # Sync COMMON projects
        common_projects = get_projects_for_platform(platform_name, 'COMMON')
        if common_projects:
            common_success = execute_repo_sync(ssh, COMMON_DIR, common_projects)
            write_json_to_file(modified_json, output_file_path)
            for each_project in common_projects:
                common_projects_path = get_path_for_project(platform_name, 'COMMON', each_project)
                if common_projects_path.endswith("make"):
                    patch_file = update_build_repo_diff_file("build_repo_sdm660_t.patch", "updated_build_repo_sdm660_t.patch",replacements)
                    apply_patch(ssh, sftp, f'{COMMON_DIR}/'+common_projects_path, patch_file)
                    push_changes_for_review(ssh, f'{COMMON_DIR}/'+common_projects_path, common_branch_name, commit_message="Retain Build Fingerprint 1/2", topic="AUTOMATED_HF_VERSIONING")
                elif common_projects_path.startswith("release"):
                    update_files_on_server(ssh, sftp, f'{COMMON_DIR}/'+common_projects_path, read_json_file(output_file_path))
                    push_changes_for_review(ssh, f'{COMMON_DIR}/'+common_projects_path, common_branch_name, commit_message="Retain Build Fingerprint 2/2", topic="AUTOMATED_HF_VERSIONING")
                else:
                    print(f"One or more apply patch commands for {each_project} failed.")
        else:
            common_success = True  # No COMMON projects to sync

        # Do something based on the success or failure of the sync commands
        if qssi_success and vendor_success and common_success:
            print(f"All repo sync commands for {platform_name} succeeded.")
        else:
            print(f"One or more repo sync commands for {platform_name} failed.")

        # Update the JiraTicket model to indicate SSH connection established
        """ ticket.ssh_connection_established = True
        ticket.hf_versioning_progress = "Pending"
        ticket.save() """
    except Exception as e:
        # Handle SSH connection errors
        print(f"Error establishing SSH connection for ticket", e)
    finally:
        # Close the SSH connection
        if ssh:
            ssh.close()
        if sftp:
            sftp.close()

#Write a method to parse build fingerprint


def ensure_remote_directories_exists(ssh, directories):
    """
    Ensures that the specified directories exist on the remote server.
    If they do not exist, they are created.
    
    Args:
    - ssh (paramiko.SSHClient): The SSH client connected to the remote server.
    - directories (list): List of directory paths to check/create.
    """
    for directory in directories:
        stdin, stdout, stderr = ssh.exec_command(f"test -d {directory} && echo 'Exists' || mkdir -p {directory}")
        result = stdout.read().decode().strip()
        if result == 'Exists':
            print(f"Directory already exists: {directory}")
        else:
            print(f"Directory created: {directory}")

def extract_repo_init_commands(input_string):
    """
    Extracts the repo init commands for QSSI and Vendor, or the legacy command from the given input string.
    
    Args:
    - input_string (str): The input string containing the commands.
    
    Returns:
    - dict: A dictionary containing the extracted commands with keys 'qssi', 'vendor', and 'legacy'.
    """
    # Define regex patterns to match the repo init commands
    qssi_pattern = r'QSSI:\s*(repo init[^\n]+)'
    vendor_pattern = r'Vendor:\s*(repo init[^\n]+)'
    legacy_pattern = r'(repo init[^\n]*)'

    # Search for the patterns in the input string
    qssi_match = re.search(qssi_pattern, input_string, re.MULTILINE)
    vendor_match = re.search(vendor_pattern, input_string, re.MULTILINE)
    
    # Check if QSSI and Vendor commands are found
    if qssi_match and vendor_match:
        qssi_command = qssi_match.group(1)
        vendor_command = vendor_match.group(1)
        return {
            'qssi': qssi_command,
            'vendor': vendor_command,
            'legacy': None
        }
    else:
        # Check for legacy command
        legacy_match = re.search(legacy_pattern, input_string, re.MULTILINE)
        legacy_command = legacy_match.group(1) if legacy_match else None
        return {
            'qssi': None,
            'vendor': None,
            'legacy': legacy_command
        }

def clear_directory(ssh, directory):
    """
    Clears the contents of the specified directory on the remote server.
    
    Args:
    - ssh (paramiko.SSHClient): The SSH client connected to the remote server.
    - directory (str): The directory to clear.
    """
    command = f"rm -rf {directory}/*"
    stdin, stdout, stderr = ssh.exec_command(command)
    exit_status = stdout.channel.recv_exit_status()  # Get the exit status of the command
    
    if exit_status == 0:
        print(f"Cleared contents of {directory}")
    else:
        print(f"Failed to clear contents of {directory}")
        print(stderr.read().decode())

def execute_repo_init(ssh, directory, repo_init_command):
    """
    Clears the directory and executes the repo init command in the specified directory on the remote server.
    
    Args:
    - ssh (paramiko.SSHClient): The SSH client connected to the remote server.
    - directory (str): The directory to navigate to.
    - repo_init_command (str): The repo init command to execute.
    
    Returns:
    - bool: True if the repo init command succeeded, False otherwise.
    """
    # Clear the directory
    clear_directory(ssh, directory)
    
    # Combine commands to navigate to the directory and execute the repo init command
    command = f"cd {directory} && {repo_init_command}"
    print(command)
    
    stdin, stdout, stderr = ssh.exec_command(command)
    exit_status = stdout.channel.recv_exit_status()  # Get the exit status of the command
    
    if exit_status == 0:
        print(f"Repo init succeeded in {directory}")
        return True
    else:
        print(f"Repo init failed in {directory}")
        print(stderr.read().decode())
        return False

def get_projects_by_type(projects_dict):
    """
    Separates projects by type (QSSI, VENDOR, COMMON).
    
    Args:
    - projects_dict (dict): Dictionary containing projects and their types.
    
    Returns:
    - dict: Dictionary with keys 'QSSI', 'VENDOR', and 'COMMON' containing lists of respective projects.
    """
    projects_by_type = {
        'QSSI': [],
        'VENDOR': [],
        'COMMON': []
    }
    
    for project, project_type in projects_dict.items():
        if project_type == 'QSSI' or project_type == 'VENDOR':
            projects_by_type[project_type].append(project)
        else:
            projects_by_type['COMMON'].append(project)
    
    return projects_by_type

def execute_repo_sync(ssh, directory, projects):
    """
    Navigates to the specified directory and executes repo sync for the given projects.
    
    Args:
    - ssh (paramiko.SSHClient): The SSH client connected to the remote server.
    - directory (str): The directory to navigate to.
    - projects (list): List of projects to sync.
    
    Returns:
    - bool: True if the repo sync command succeeded, False otherwise.
    """
    # Join the projects into a single repo sync command
    projects_str = ' '.join(projects)
    command = f"cd {directory} && repo sync {projects_str} -j32"
    
    stdin, stdout, stderr = ssh.exec_command(command)
    exit_status = stdout.channel.recv_exit_status()  # Get the exit status of the command
    
    if exit_status == 0:
        print(f"Repo sync succeeded in {directory}")
        return True
    else:
        print(f"Repo sync failed in {directory}")
        print(stderr.read().decode())
        return False

def parse_build_fingerprint(build_string):
    """
    Parses the given build string and extracts the required components.
    
    Args:
    - build_string (str): The build string to parse.
    
    Returns:
    - dict: A dictionary containing the extracted components.
    """
    # Define regex patterns to extract the components
    gms_pattern = re.compile(r'(\d{2}-\d{2}-\d{2}\.\d{2}-TG)')
    ngms_pattern = re.compile(r'(\d{2}-\d{2}-\d{2}\.\d{2}-TN)')
    build_number_pattern = re.compile(r'(\d+):user')
    basefile_pattern = re.compile(r'(\d{2}-\d{2}-\d{2}\.\d{2}-TG-[^/]+)')
    patch_string_pattern = re.compile(r'-(U\d{2})-')

    # Extract components using regex
    gms_match = gms_pattern.search(build_string)
    ngms_match = ngms_pattern.search(build_string)
    build_number_match = build_number_pattern.search(build_string)
    basefile_match = basefile_pattern.search(build_string)
    patch_string_match = patch_string_pattern.search(build_string)
    
    # Construct basefile_gms and basefile_nongms
    if basefile_match:
        basefile_gms = basefile_match.group(1)
        basefile_nongms = basefile_gms.replace('-TG-', '-TN-')
        
        # Check if basefile_gms contains "HEL" and starts with "13"
        if "HEL" in basefile_gms and basefile_gms.startswith("13"):
            # Generate incremented versions
            basefile_gms_incremented = increment_basefile_version(basefile_gms)
            basefile_nongms_incremented = increment_basefile_version(basefile_nongms)
            
            # Combine original and incremented versions
            basefile_gms_combined = f"{basefile_gms};{basefile_gms_incremented}"
            basefile_nongms_combined = f"{basefile_nongms};{basefile_nongms_incremented}"
        else:
            basefile_gms_combined = basefile_gms
            basefile_nongms_combined = basefile_nongms
    else:
        basefile_gms_combined = None
        basefile_nongms_combined = None

    # Extract the matched components
    gms_baseline = gms_match.group(1) if gms_match else None
    ngms_baseline = gms_baseline.replace('-TG', '-TN') if gms_baseline else None
    build_number = build_number_match.group(1) if build_number_match else None
    build_id_patch_string = patch_string_match.group(1) if patch_string_match else None
    build_id_without_baselinegms = basefile_gms.replace(gms_baseline, "") if basefile_gms else None
    build_id_without_baselinengms = basefile_nongms.replace(ngms_baseline, "") if basefile_nongms else None

    return {
        'GMS_BASELINE': gms_baseline,
        'NGMS_BASELINE': ngms_baseline,
        'BUILD_NUMBER': build_number,
        'basefile_gms': basefile_gms_combined,
        'basefile_nongms': basefile_nongms_combined,
        'BUILD_ID_PATCH_STRING': build_id_patch_string,
        'BUILD_ID_WITHOUT_BASEFILEGMS': build_id_without_baselinegms,
        'BUILD_ID_WITHOUT_BASEFILENGMS': build_id_without_baselinengms
    }

def increment_basefile_version(basefile):
    """
    Increments the version number in the basefile string.
    
    Args:
    - basefile (str): The basefile string to increment.
    
    Returns:
    - str: The incremented basefile string.
    """
    version_pattern = re.compile(r'(\d{2}-\d{2}-\d{2}\.)(\d{2})')
    match = version_pattern.search(basefile)
    
    if match:
        major_version = match.group(1)
        minor_version = int(match.group(2))
        incremented_minor_version = f"{minor_version + 1:02d}"
        incremented_basefile = basefile.replace(f"{major_version}{minor_version:02d}", f"{major_version}{incremented_minor_version}")
        return incremented_basefile
    return basefile


def update_json_with_parsed_values(input_json, parsed_values):
    """
    Updates the input JSON with values extracted from the build string.
    
    Args:
    - input_json (dict): The input JSON dictionary.
    - parsed_values (dict): Dictionary containing values extracted from the build string.
    
    Returns:
    - dict: The modified JSON dictionary.
    """
    # Update baseline_patch_config.sh section
    input_json["baseline_patch_config.sh"]["existing"]["GMS_BASELINE"] = parsed_values["GMS_BASELINE"]
    input_json["baseline_patch_config.sh"]["existing"]["NGMS_BASELINE"] = parsed_values["NGMS_BASELINE"]
    input_json["baseline_patch_config.sh"]["existing"]["BUILD_ID_PATCH_STRING"] = parsed_values["BUILD_ID_PATCH_STRING"]
    input_json["baseline_patch_config.sh"]["pattern"]["BUILD_NUMBER"] = parsed_values["BUILD_NUMBER"]

    # Update basefile section
    input_json["osu3/basefile"]["existing"]["basefile_gms"] = parsed_values["basefile_gms"]
    input_json["osu3/basefile"]["existing"]["basefile_nongms"] = parsed_values["basefile_nongms"]

    return input_json

def read_json_file(file_path):
    """
    Reads a JSON file and returns the data.
    
    Args:
    - file_path (str): The path to the JSON file.
    
    Returns:
    - dict: The JSON data.
    """
    with open(file_path, 'r') as file:
        data = json.load(file)
    return data

def write_json_to_file(data, file_path):
    """
    Writes JSON data to a file.
    
    Args:
    - data (dict): The JSON data.
    - file_path (str): The path to the output JSON file.
    """
    with open(file_path, 'w', newline='\n') as file:
        json.dump(data, file, indent=4)

def update_build_repo_diff_file(diff_file_path, output_file_path, replacements):
    """
    Updates the placeholders in the diff file with the given dictionary values.
    
    Args:
    - diff_file_path (str): The path to the diff file.
    - output_file_path (str): The path to the output file to write the updated content.
    - replacements (dict): The dictionary containing the replacement values.
    """
    # Read the diff file
    with open(diff_file_path, 'r') as file:
        content = file.read()

    # Replace placeholders with values from the dictionary
    for key, value in replacements.items():
        placeholder = f'{{{key}}}'
        content = content.replace(placeholder, value)

    # Write the updated content to the output file
    with open(output_file_path, 'w', newline='\n') as file:
        file.write(content)

    return output_file_path

def apply_patch(ssh, sftp, directory, patch_file):
    """
    Copies the patch file to the specified directory and applies it.
    
    Args:
    - ssh (paramiko.SSHClient): The SSH client connected to the remote server.
    - sftp (paramiko.SFTPClient): The SFTP client connected to the remote server.
    - directory (str): The directory to navigate to.
    - patch_file (str): The local path to the patch file to copy and apply.
    
    Returns:
    - bool: True if the patch command succeeded, False otherwise.
    """
    # Copy the patch file to the remote directory
    remote_patch_file = f'{directory}/'+ os.path.basename(patch_file)
    sftp.put(patch_file, remote_patch_file)
    print(f"Copied patch file to {remote_patch_file}")
    
    # Apply the patch
    command = f"cd {directory} && git apply {remote_patch_file}"
    
    stdin, stdout, stderr = ssh.exec_command(command)
    exit_status = stdout.channel.recv_exit_status()  # Get the exit status of the command
    
    if exit_status == 0:
        print(f"Patch applied successfully in {directory}")
        # Remove the patch file from the server
        sftp.remove(remote_patch_file)
        print(f"Removed patch file from {directory}")
        return True
    else:
        print(f"Failed to apply patch in {directory}")
        print(stderr.read().decode())
        return False

def increment_minor_version(value):
    """
    Increments the minor version number in the given value.
    
    Args:
    - value (str): The value to increment the minor version for.
    
    Returns:
    - str: The value with the incremented minor version.
    """
    version_pattern = re.compile(r'(\d{2}-\d{2}-\d{2}\.)(\d{2})(-TG|-TN)')
    match = version_pattern.search(value)
    if match:
        major_version = match.group(1)
        minor_version = int(match.group(2))
        suffix = match.group(3)
        incremented_minor_version = f"{minor_version + 1:02d}"
        return f"{major_version}{incremented_minor_version}{suffix}"
    return value

def update_file_content(file_content, updates, file_name):
    """
    Updates the file content based on the given updates.
    
    Args:
    - file_content (str): The original file content.
    - updates (dict): The updates to apply to the file content.
    - file_name (str): The name of the file being updated.
    
    Returns:
    - str: The updated file content.
    """
    if file_name == "baseline_patch_config.sh":
        # Update key-value pairs for baseline_patch_config.sh
        keys_to_update = ['GMS_BASELINE', 'NGMS_BASELINE', 'IS_HOTFIX_ENABLED']
        for key in keys_to_update:
            if key in updates.get('existing', {}):
                value = updates['existing'][key]
                pattern = re.compile(rf'^([#\s]*)export {key}=.*$', re.MULTILINE)
                match = re.search(pattern, file_content)
                if match:
                    indentation = match.group(1)
                    file_content = re.sub(pattern, f'{indentation}export {key}={value}', file_content)
                else:
                    # If the key is not found, add the key-value pair at the end of the file
                    file_content += f'\nexport {key}={value}'

        # Insert BUILD_NUMBER based on the pattern
        pattern_info = updates.get('pattern', {})
        if 'pattern' in pattern_info and 'BUILD_NUMBER' in pattern_info:
            pattern_to_find = pattern_info['pattern']
            build_number = pattern_info['BUILD_NUMBER']
            build_number_line = f'BUILD_NUMBER={build_number}'
            
            # Insert the build number line after the matching pattern
            pattern_to_find_re = re.compile(re.escape(pattern_to_find), re.MULTILINE)
            file_content = re.sub(pattern_to_find_re, f'{pattern_to_find}\n    {build_number_line}', file_content)

        # Special case handling for RESIZE_SYSTEM_IMAGE
        resize_system_image_pattern = re.compile(r'if \[\s*"\$RESIZE_SYSTEM_IMAGE"\s*=\s*"true"\s*\];\s*then(.*?)else(.*?)fi', re.DOTALL)
        resize_system_image_match = resize_system_image_pattern.search(file_content)
        if resize_system_image_match:
            resize_block_if = resize_system_image_match.group(1)
            resize_block_else = resize_system_image_match.group(2)

            # Increment the values in the 'if' block
            gms_value = updates['existing'].get('GMS_BASELINE', '13-29-10.00-TG')
            ngms_value = updates['existing'].get('NGMS_BASELINE', '13-29-10.00-TN')
            gms_value_incremented = increment_minor_version(gms_value)
            ngms_value_incremented = increment_minor_version(ngms_value)

            resize_block_if = re.sub(r'^([#\s]*)export GMS_BASELINE=.*$', rf'\1export GMS_BASELINE={gms_value_incremented}', resize_block_if, flags=re.MULTILINE)
            resize_block_if = re.sub(r'^([#\s]*)export NGMS_BASELINE=.*$', rf'\1export NGMS_BASELINE={ngms_value_incremented}', resize_block_if, flags=re.MULTILINE)

            # Use the original values in the 'else' block
            resize_block_else = re.sub(r'^([#\s]*)export GMS_BASELINE=.*$', rf'\1export GMS_BASELINE={gms_value}', resize_block_else, flags=re.MULTILINE)
            resize_block_else = re.sub(r'^([#\s]*)export NGMS_BASELINE=.*$', rf'\1export NGMS_BASELINE={ngms_value}', resize_block_else, flags=re.MULTILINE)

            file_content = file_content[:resize_system_image_match.start(1)] + resize_block_if + file_content[resize_system_image_match.start(2):resize_system_image_match.start(2)] + "else" + resize_block_else + file_content[resize_system_image_match.end(2):]

    elif file_name == "osu3/basefile":
        # Update key-value pairs for osu3/basefile
        for key, value in updates.get('existing', {}).items():
            pattern = re.compile(rf'^([#\s]*){key}=.*$', re.MULTILINE)
            match = re.search(pattern, file_content)
            if match:
                indentation = match.group(1)
                if key in {"artifactory_repository_name", "build_enabled"}:
                    # Do not enclose these values in quotes
                    file_content = re.sub(pattern, f'{indentation}{key}={value}', file_content)
                else:
                    # Enclose other values in quotes
                    file_content = re.sub(pattern, f'{indentation}{key}="{value}"', file_content)

    return file_content

def ensure_specific_vars_at_end(file_content, updates):
    """
    Ensures that specific variables are updated at the end of the file.
    
    Args:
    - file_content (str): The original file content.
    - updates (dict): The updates to apply to the file content.
    
    Returns:
    - str: The updated file content.
    """
    specific_keys = ['BUILD_ID_PATCH_STRING', 'IS_PRODUCT_TRANSITIONED_TO_MR', 'BUILD_ID_HOTFIX_MODIFIER']
    
    # Split content into lines
    lines = file_content.splitlines()
    
    # Remove existing definitions of specific keys at the end
    end_section_lines = []
    while lines and any(re.match(rf'^[#\s]*export {key}=.*$', lines[-1]) for key in specific_keys):
        line = lines.pop()
        if any(re.match(rf'^[#\s]*export {key}=.*$', line) for key in specific_keys):
            continue
        end_section_lines.append(line)
    end_section_lines.reverse()  # Restore the order of end section lines

    # Add updated definitions of specific keys to the end
    for key in specific_keys:
        if key in updates.get('existing', {}):
            value = updates['existing'][key]
            end_section_lines.append(f'export {key}={value}')
    
    # Combine the content back
    file_content = '\n'.join(lines + end_section_lines) + '\n'
    return file_content

def update_files_on_server(ssh, sftp, directory, json_content):
    """
    Updates the files on the server based on the given JSON content.
    
    Args:
    - ssh (paramiko.SSHClient): The SSH client connected to the server.
    - sftp (paramiko.SFTPClient): The SFTP client connected to the server.
    - directory (str): The directory on the server where the files are located.
    - json_content (dict): The JSON content with the updates.
    """
    for file_name, updates in json_content.items():
        remote_file_path = f'{directory}/{file_name}'
        
        # Read the original file content
        with sftp.open(remote_file_path, 'r') as file:
            file_content = file.read().decode('utf-8')  # Decode bytes to string
        
        # Update the file content
        updated_content = update_file_content(file_content, updates, file_name)
        
        # Ensure specific variables are at the end of the file for baseline_patch_config.sh
        if file_name == "baseline_patch_config.sh":
            updated_content = ensure_specific_vars_at_end(updated_content, updates)
        
        # Write the updated content back to the file
        with sftp.open(remote_file_path, 'w') as file:
            file.write(updated_content)
        print(f"Updated file: {remote_file_path}")

def checkout_branch_via_ssh(ssh, repo_path, branch_name):
    try:
        # Command to change directory to the repository and checkout the branch
        command = f'cd {repo_path} && git checkout {branch_name}'

        # Execute the command
        stdin, stdout, stderr = ssh.exec_command(command)

        # Read the outputs and errors
        output = stdout.read().decode()
        error = stderr.read().decode()

        # Check for errors in stderr
        if error:
            print(f"Error checking out branch: {error}")
        else:
            print(f"Successfully checked out to branch {branch_name}:\n{output}")

    except Exception as e:
        print(f"An error occurred: {e}")

def push_changes_for_review(ssh, directory, branch, commit_message, topic):
    """
    Pushes the applied changes to the remote repository for review.
    
    Args:
    - ssh (paramiko.SSHClient): The SSH client connected to the server.
    - directory (str): The directory on the server where the files are located.
    - branch (str): The branch to push the changes to.
    - commit_message (str): The commit message for the changes.
    - topic (str): The topic for the review.
    """
    # Escape the commit message and topic to handle special characters
    commit_message_escaped = shlex.quote(commit_message)
    topic_escaped = shlex.quote(topic)
    
    commands = [
        f"cd {directory}",
        "git add .",
        f"git commit -m {commit_message_escaped}",
        f"git push caf HEAD:refs/for/{branch}%topic={topic_escaped}"
    ]
    full_command = " && ".join(commands)
    
    stdin, stdout, stderr = ssh.exec_command(full_command)
    exit_status = stdout.channel.recv_exit_status()  # Get the exit status of the command
    
    if exit_status == 0:
        print(f"Changes pushed to branch {branch} for review with topic '{topic}'.")
    else:
        print(f"Failed to push changes for review.")
        print(stderr.read().decode())

def derive_platform_name(build_fingerprint):
    # Mapping of product codes to platform values
    product_code_to_platform = {
        "HEL": "SDM660",
        "WTX": "SDW410",
        "ATH": "SDM6490",
        "GRT": "SDM6375",
        "GSE": "SDM6375",
        "NEM": "SDM4490"
    }

    # Mapping of Android version numbers to their alphabetic representations
    version_to_alphabet = {
        8: "O",  # Oreo
        9: "P",  # Pie
        10: "Q",  # Quince Tart (unofficial)
        11: "R",  # Red Velvet Cake
        12: "S",  # Snow Cone
        13: "T",  # Tiramisu
        14: "U",  # Upside Down Cake (unofficial, future version)
        # Add more mappings as needed
    }

    try:
        # Extract parts from the build fingerprint
        parts = build_fingerprint.split(':')
        print(len(parts[2].split('-')))
        product_info = parts[0].split('/')
        android_version = int(parts[1].split('/')[0])
        product_code = parts[1].split('/')[1].split('-')[6]

        # Get platform value from the product code
        platform_value = product_code_to_platform.get(product_code)

        # Convert Android version to its alphabetic representation
        os_version = version_to_alphabet.get(android_version)

        if platform_value and os_version:
            # Combine platform value and OS version to form the platform name
            platform_name = f"{platform_value}-{os_version}"
            return platform_name
        else:
            raise ValueError("Invalid build fingerprint or mapping not found.")
    except Exception as e:
        return f"Error deriving platform name: {e}"
    
def get_branch_name_from_input(input_string, parameter):
    """
    Returns the branch name based on the given parameter by parsing the repo init command.
    
    Args:
    - input_string (str): The input string containing the repo init command(s).
    - parameter (str): The parameter indicating the type (QSSI, VENDOR, COMMON).
    
    Returns:
    - str: The extracted branch name.
    """
    # Define the regex pattern to extract the branch name based on the -b flag
    pattern = r'-b\s+([^\s]+)'

    # Split the input string into lines
    lines = input_string.splitlines()

    # Dictionary to hold commands based on type
    commands = {
        "QSSI": None,
        "VENDOR": None,
        "COMMON": None
    }

    current_type = None

    # Iterate over lines and categorize commands
    for line in lines:
        line = line.strip()
        if line.endswith(':'):
            current_type = line[:-1].upper()
        elif line.startswith('repo init'):
            if current_type in commands:
                commands[current_type] = line
            else:
                # If no type is given, assume it is COMMON
                commands["COMMON"] = line

    try:
        # Based on the parameter, select the corresponding command
        command = commands.get(parameter.upper())

        if not command:
            raise ValueError(f"No command found for parameter: {parameter}")

        # Find the branch name in the selected command
        matches = re.findall(pattern, command)

        if not matches:
            raise ValueError("No branch name found in the command.")

        return matches[0]

    except Exception as e:
        return f"Error: {e}"

# Example usage
input_string = """
QSSI:
repo init -u ssh://gerrit.zebra.com:29418/ZEUS/manifest -b ecrt-6490-13t-zqssi-main-nov-release-cancom-hf -m ecrt-6490-13t-zqssi-main-nov-release-cancom-hf.xml --reference=$MIRROR --repo-url=ssh://gerrit.zebra.com:29418/SCM/git-repo --no-repo-verify -g all,notdefault
Vendor:
repo init -u ssh://gerrit.zebra.com:29418/ZEUS/manifest -b ecrt-6490-13t-soc-main-nov-release-cancom-hf -m ecrt-6490-13t-soc-main-nov-release-cancom-hf.xml --reference=$MIRROR --repo-url=ssh://gerrit.zebra.com:29418/SCM/git-repo --no-repo-verify -g all,notdefault
"""

# input_string = """repo init --reference="$MIRROR" -u ssh://gerrit.zebra.com:29418/ZEUS/manifest -b ecrt-sdm660t-wave2-13-32-14-u00-hf -m ecrt-sdm660t-wave2-13-32-14-u00-hf.xml --repo-url=ssh://gerrit.zebra.com:29418/SCM/git-repo --no-repo-verify -g all,notdefault"""

projects_dict_6490 = {'ZEUS/Athena/platform/release/target_files': 'VENDOR', 'ZEUS/Common/platform/build_repo': 'QSSI', 'ZEUS/Common/platform/system/core': 'QSSI'}
projects_dict = {'ZEUS/Helios/platform/release/target_files':'COMMON', }

build_string = "Zebra/TC53/TC53:13/13-34-23.00-TG-U00-STD-ATH-04/419:user/release-keys"
build_string_sdm = "Zebra/TC57XS/TC57X:13/13-32-14.00-TG-U00-STD-HEL-04/409:user/release-keys"
# parsed_result = parse_build_fingerprint(build_string)
#print(parsed_result)

#platform = 'SDM660-T'

platform = 'SDM6490-T'

# input_file_path = 'target_files_changes_' +platform+'.json'  # Path to your input JSON file
# output_file_path = 'updated_target_files_changes_'+platform+'.json' #Path to output JSON file

# # Read the input JSON file
# input_json = read_json_file(input_file_path)

# Update the JSON with the parsed values
# modified_json = update_json_with_parsed_values(input_json, parsed_result)

# Print the modified JSON string
#print(json.dumps(modified_json, indent=4))
# print(type(json.dumps(modified_json)))

# Example usage
""" diff_file_path = 'build_repo_6490_t.patch'  # Path to your diff file
output_file_path = 'updated_build_repo_6490_t.patch'  # Path to the output file """
diff_file_path = 'system_core_6490_t.patch'  # Path to your diff file
output_diff_file_path = 'updated_system_core_6490_t.patch'  # Path to the output file

#update_build_repo_diff_file(diff_file_path, output_file_path, parse_build_fingerprint(build_string))

generate_hf_versioning_patches(input_string, build_string)
# print(derive_platform_name(build_string_sdm))
#print(extract_repo_init_commands(input_string))
#print(parse_build_fingerprint(build_string_6490))
#print(get_branch_name_from_input(input_string, "COMMON"))