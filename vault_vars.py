#!/usr/bin/env python
import yaml

def get_vault(vaultfile):
    from ansible.parsing import vault
    from ansible.parsing.dataloader import DataLoader

    loader = DataLoader()
    secret = vault.get_file_vault_secret(filename=vaultfile, loader=loader)
    secret.load()
    vault_secrets = [('default', secret)]
    return vault.VaultLib(vault_secrets)
    

def read(filename, vaultfile):
    from ansible.parsing.yaml.loader import AnsibleLoader
    # Load vault password and prepare secrets for decryption
    _vault = get_vault(vaultfile)

    # Load encrypted yml for processing
    with open(filename, 'r', encoding='utf-8') as f:
        loaded_yaml = AnsibleLoader(f, vault_secrets=_vault.secrets).get_single_data()

    return loaded_yaml


# data format dict: 2 root keys _encrypt,_plaintext
def write(filename, data):
    # Modify yml with new encrypted values
    from ansible.parsing.yaml.dumper import AnsibleDumper
    # Write a new encrypted yml
    with open(filename,'w') as f:
        yaml.dump(data, f, Dumper=AnsibleDumper, encoding='utf-8', default_flow_style=False)

def encrypt_vars(data: dict, vaultfile: str, key: str, value: str):
    from ansible.parsing.yaml import objects

    _vault = get_vault(vaultfile)

    subdict = data
    spl_key = key.split('.')
    for e in spl_key[:-1]:
        subdict[e] = subdict.get(e,{})
        subdict  = subdict[e]

    # encrypt value
    enc_value = objects.AnsibleVaultEncryptedUnicode.from_plaintext(value, _vault, _vault.secrets[0][1])

    # enplace value
    subdict[spl_key[-1]] = enc_value

    return data # src data is modified during the process...


if __name__ == '__main__':
    # todo argparser etc... for non lib usage
    pass
