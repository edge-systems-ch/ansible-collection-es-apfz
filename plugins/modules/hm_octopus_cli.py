#!/usr/bin/python
# -*- coding: utf-8 -*-

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'status': ['preview'],
    'supported_by': 'community'
}

DOCUMENTATION = r'''
---
module: hm_octopus_cli
short_description: Execute CLI commands on Hirschmann Octopus 1 & 2 switches
version_added: "1.0.0"
author: "Edge Systems"
description:
  - This module provides a pexpect-based terminal interaction for Hirschmann switches.
  - Optimized for Octopus 1 (Classic) using Latin-1 encoding and Octopus 2 (HiOS) handling pager and logout save prompts.
  - Preserves the shell session look (prompts and echoes) in stdout while providing a clean log for debugging.
  - This module is part of the 'es.apfz' collection.
requirements:
  - python >= 3.9
  - pexpect
  - sshpass
options:
  host:
    description:
      - The IP address or hostname of the switch.
    required: true
    type: str
  user:
    description:
      - SSH username for authentication.
    required: false
    type: str
    default: admin
  password:
    description:
      - SSH password for authentication.
    required: false
    type: str
    no_log: true
  lines:
    description:
      - A list of CLI commands to execute in order.
    required: true
    type: list
  save:
    description:
      - If set to true, the module will answer 'yes' to any 'save changes' prompts during logout.
    required: true
    type: bool
notes:
  - Check mode is not supported as commands are executed directly on the terminal.
'''

RETURN = r'''
log:
    description: Full interaction history including internal Ansible markers for debugging.
    returned: always
    type: list
    elements: str
stdout:
    description: The shell session output, including prompts and command echoes, but without internal markers.
    returned: always
    type: str
'''

import re
import time
import pexpect
from ansible.module_utils.basic import AnsibleModule

def clean_octopus_output(text, remove_markers=False):
    """
    Cleans pager/ANSI artifacts and optionally internal markers.
    Preserves prompts and command echoes for stdout.
    """
    text = re.sub(r'--More-- or \(q\)uit', '', text)
    text = re.sub(r'\x1b\[[0-9;]*[mGJKHFp]', '', text)
    # Remove progress bar artifacts [=======]
    text = re.sub(r'\[[-=]+\]', '', text)

    lines = text.splitlines()
    cleaned = []
    for line in lines:
        l = line.replace('\r', '').strip()
        if remove_markers and l.startswith('### COMMAND:'):
            continue
        if l:
            cleaned.append(l)
    return "\n".join(cleaned)

def run_pexpect_session(module, host, user, password, lines, save_conf):
    dest = f"{user}@{host}" if user else host
    cmd = f"sshpass -p {password} ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null {dest}" if password else \
          f"ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null {dest}"

    prompt_regex = r'(?:\r\n|\r|^).*?\(.*?OCTOPUS\).*?[>#]'
    pager_regex = r'--More-- or \(q\)uit'

    full_output = ""

    try:
        child = pexpect.spawn(cmd, encoding='latin-1', timeout=30, dimensions=(1000, 200))
        child.expect([r'[>#]', prompt_regex])

        for line in lines:
            child.sendline("")
            child.expect(prompt_regex)

            child.sendline(line)
            full_output += f"\n### COMMAND: {line}\n"

            command_result = ""
            while True:
                idx = child.expect([prompt_regex, pager_regex, pexpect.TIMEOUT], timeout=15)
                command_result += child.before
                if idx == 0:
                    command_result += child.after
                    break
                elif idx == 1:
                    child.send(" ")
                    continue
                else:
                    break
            full_output += command_result

        # Logout Sequence
        for _ in range(3):
            child.sendline("exit")
            idx = child.expect([prompt_regex, r'[Ss]ave', r'[Aa]re you sure', pexpect.TIMEOUT], timeout=2)
            if idx in [1, 2]: break

        child.sendline("logout")

        for _ in range(4):
            idx = child.expect([
                r'[Aa]re you sure',
                r'[Uu]nsaved',
                r'\(y/n\)',
                prompt_regex,
                pexpect.EOF
            ], timeout=25)

            if idx == 0 or idx == 2:
                child.sendline("y")
            elif idx == 1:
                child.sendline("y" if save_conf else "n")
                if save_conf: time.sleep(1)
            elif idx == 3:
                child.sendline("logout")
            else:
                break

    except Exception as e:
        module.fail_json(msg=f"Interaction Error: {str(e)}", log=clean_octopus_output(full_output).splitlines())

    return full_output

def main():
    module = AnsibleModule(
        argument_spec=dict(
            user=dict(required=False, type="str", default="admin"),
            password=dict(required=False, type="str", no_log=True),
            host=dict(required=True, type="str"),
            lines=dict(required=True, type="list"),
            save=dict(required=True, type="bool"),
        ),
        supports_check_mode=False
    )

    if module.check_mode:
        module.exit_json(skipped=True, msg="Check mode is not supported.")

    raw_output = run_pexpect_session(
        module, module.params["host"], module.params["user"],
        module.params["password"], module.params["lines"], module.params["save"]
    )

    log_content = clean_octopus_output(raw_output, remove_markers=False)
    stdout_content = clean_octopus_output(raw_output, remove_markers=True)

    has_enable = any("enable" in str(l).lower() for l in module.params["lines"])
    has_configure = any("configure" in str(l).lower() for l in module.params["lines"])

    module.exit_json(
        changed=(has_enable or has_configure or module.params["save"]),
        log=log_content.splitlines(),
        stdout=stdout_content
    )

if __name__ == "__main__":
    main()