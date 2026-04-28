"""Default checked-in files for ``keysmith team init``."""

TEAM_YAML = """# KeySmith team (commit this). age public keys for encrypted secret sharing.
team:
  name: my-team
  members:
    - name: You
      email: you@example.com
      role: admin
      pubkey: age1REPLACE_WITH_YOUR_PUBLIC_KEY

  settings:
    require_receipts: true
    default_rotation_days: 90
    health_check_required: true

  credential_sharing:
    method: age
    shared_credentials: []
    personal_credentials: []
"""

CREDENTIALS_YAML = """# Optional: checked-in credential requirements (can complement code scan).
project: my-project

credentials: {}
"""

ROTATION_POLICY_YAML = """# Team rotation targets (commit). Local reminders use ``keysmith set-rotation`` too.
policies: {}

settings:
  enforce: false
  grace_period_days: 7
"""
