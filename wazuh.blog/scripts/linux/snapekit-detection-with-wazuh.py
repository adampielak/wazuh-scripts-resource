<!-- Source: https://wazuh.com/blog/snapekit-detection-with-wazuh/ | Article: Snapekit detection with Wazuh -->
#!/usr/bin/env python3

from elftools.elf.elffile import ELFFile

def unpack_data_from_elf(file_path, start_address, length):
    with open(file_path, 'rb') as f:
        elffile = ELFFile(f)
        section = elffile.get_section_by_name('.data')
        if section is None:
            print('No .data section found in ELF file.')
            return

        section_offset = section['sh_offset']
        file_offset = start_address - section['sh_addr'] + section_offset
        f.seek(file_offset)
        data = f.read(length)

        with open('snapekit.ko', 'wb') as output_file:
            output_file.write(data)

        print(f'Data extracted to snapekit.ko, length: {length} bytes.')

# Define the parameters
file_path = '/home/user1/snapekit/2600eb7673dddacda0e780bf3b163b0b89b41f9925eebbd2a2b3dfa234bc1a22.elf'
start_address = 0x5100
length = 0xc4df8

# Run the function
unpack_data_from_elf(file_path, start_address, length)