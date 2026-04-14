# WIP: Ansible Baseline Security

**Note**: This is all work in progress.  No guarantees are made regarding
stability or functionality.  Do not use this unless you know what you are
doing.

A set of ansible playbooks, roles, vars, files, and everything else needed to
provide a baseline level of security to a network.  This does not comply with
any cybersecurity recommendations or regulations, nor is compliance a goal.

### Usage

1. Populate the hosts file changing the provided settings as necessary
2. Create the file `vars/passwords.yml` using the provided template
3. Create the file `vars/management.yml` using the provided template
4. Run the appropriate playbooks

### Manual Steps (not handled by Ansible)

- **Kernel updates**: Must be done manually per-host. Ansible does not update
  the kernel due to distro-specific differences and reboot requirements.
- **Firewall configuration**: Must be configured manually per-host. Each host
  has different scored services and network requirements.

### Contributing

Pull requests are welcome!

### Legal

Copyright (c) Cody Ho <codyho@stanford.edu>

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) version 3 of the License.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
