built with zig 0.11 => just run "zig build"

This was made because I did not like the vim gpg plugin and wanted to implement aes for fun.
- put script copen into path after changing the NORMAL_USER variable to your username
- put alias copen="doas copen" into .bashrc
- in /etc/doas.conf add:
    - permit keepenv nopass root as <your user>
    - permit nopass <your user> cmd <absolute path to copen>
Then you can encrypt a file with "aes encrypt file.txt file.txt" and open it in neovim
with "copen file.txt". This will decrypt the file and put the plaintext into a newly
mounted mfs (memory file system) directory /tmp/aes-decrypted-dir/.
After you are done editing, the directory is unmounted and the plaintext should be gone forever.
By default copen uses the "nvim -n" command (disables swapfiles), but you can also pass a different program
as further arguments to copen.

example (go to page 5): copen document.pdf zathura -P 5

CTR mode encrypted data has the following file format:
- first block is random initialization vector
- the rest is ciphertext (AES256)
- 32 byte key is derived with scrypt from password
- the first 2 blocks of the ciphertext are a random password validator:
    - check if AES256(validator[1st block], key=0) == validator[2nd block]
=> I think this is secure, but most likely it's not
