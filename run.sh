#!/usr/bin/env sh
ansible-galaxy collection install /storage/af/user/jbalcas/work/sdn-sense/ansible_collections/sense/dellos10/ --force
ansible-galaxy collection install /storage/af/user/jbalcas/work/sdn-sense/ansible_collections/sense/freertr/ --force
python3 test-runner.py
