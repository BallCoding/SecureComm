# Third-Party Notices

This project includes or relies on the following third-party packages.

## Python Dependencies

1. Package: `cryptography`  
   Version: `46.0.5`  
   License: `Apache-2.0 OR BSD-3-Clause`  
   Metadata: `vendor/cryptography-46.0.5.dist-info/METADATA`  
   License files:  
   - `vendor/cryptography-46.0.5.dist-info/licenses/LICENSE`  
   - `vendor/cryptography-46.0.5.dist-info/licenses/LICENSE.APACHE`  
   - `vendor/cryptography-46.0.5.dist-info/licenses/LICENSE.BSD`

2. Package: `argon2-cffi`  
   Version: `25.1.0`  
   License: `MIT`  
   Metadata: `vendor/argon2_cffi-25.1.0.dist-info/METADATA`  
   License file:  
   - `vendor/argon2_cffi-25.1.0.dist-info/licenses/LICENSE`

3. Package: `argon2-cffi-bindings`  
   Version: `25.1.0`  
   License: `MIT`  
   Metadata: `vendor/argon2_cffi_bindings-25.1.0.dist-info/METADATA`  
   License file:  
   - `vendor/argon2_cffi_bindings-25.1.0.dist-info/licenses/LICENSE`

4. Package: `cffi`  
   Version: `2.0.0`  
   License: `MIT`  
   Metadata: `vendor/cffi-2.0.0.dist-info/METADATA`  
   License files:  
   - `vendor/cffi-2.0.0.dist-info/licenses/LICENSE`  
   - `vendor/cffi-2.0.0.dist-info/licenses/AUTHORS`

5. Package: `pycparser`  
   Version: `3.0`  
   License: `BSD-3-Clause`  
   Metadata: `vendor/pycparser-3.0.dist-info/METADATA`  
   License file:  
   - `vendor/pycparser-3.0.dist-info/licenses/LICENSE`

## Notes

- If you choose not to commit `vendor/`, dependencies can be recreated by:
  `python -m pip install --target vendor -r requirements.txt`
- Keep third-party license files intact when redistributing this project.
