import sys

class CustomBase64EncoderDecoder:
    ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    PADDING_CHAR = "="
    COMMENT_START_CHAR = "_"
    LINE_LENGTH = 76

    @staticmethod
    def encode_file(input_file, output_file=None):
        try:
            with open(input_file, 'rb') as file:
                binary_data = file.read()

            base64_data = CustomBase64EncoderDecoder.encode(binary_data)

            if output_file is None:
                output_file = input_file[:input_file.rfind('.')] + '.base64'

            with open(output_file, 'w') as file:
                file.write(base64_data)

            print(f"Файл '{input_file}' успішно закодовано та збережено як '{output_file}'.")
        except Exception as e:
            print(f"Помилка кодування файлу '{input_file}': {e}")

    @staticmethod
    def decode_file(input_file, output_file=None):
        try:
            with open(input_file, 'r') as file:
                base64_data = file.read()

            if output_file is None:
                if input_file.endswith('.base64'):
                    output_file = input_file[:-7]
                else:
                    output_file = input_file[:input_file.rfind('.')] + '_decoded'

            decoded_data = CustomBase64EncoderDecoder.decode(base64_data)

            with open(output_file, 'wb') as file:
                file.write(decoded_data)

            print(f"Файл '{input_file}' успішно розкодовано та збережено як '{output_file}'.")
        except Exception as e:
            print(f"Помилка розкодування файлу '{input_file}': {e}")

    @staticmethod
    def encode(binary_data):
       encoded_data = ''
       chunks = [binary_data[i:i + 3] for i in range(0, len(binary_data), 3)]

       for chunk in chunks:
            encoded_chunk = CustomBase64EncoderDecoder.encode_chunk(chunk)
            encoded_data += encoded_chunk

    # Split the encoded_data into lines of 76 characters each
       lines = [encoded_data[i:i + CustomBase64EncoderDecoder.LINE_LENGTH] for i in range(0, len(encoded_data), CustomBase64EncoderDecoder.LINE_LENGTH)]
       formatted_data = '\n'.join(lines)

       return formatted_data

    @staticmethod
    def encode_chunk(chunk):
        encoded_chunk = ''

        if len(chunk) == 1:
            chunk = chunk + b'\x00\x00'
            encoded_chunk += CustomBase64EncoderDecoder.ALPHABET[chunk[0] >> 2]
            encoded_chunk += CustomBase64EncoderDecoder.ALPHABET[((chunk[0] & 0x03) << 4) | (chunk[1] >> 4)]
            encoded_chunk += CustomBase64EncoderDecoder.PADDING_CHAR * 2
        elif len(chunk) == 2:
            chunk = chunk + b'\x00'
            encoded_chunk += CustomBase64EncoderDecoder.ALPHABET[chunk[0] >> 2]
            encoded_chunk += CustomBase64EncoderDecoder.ALPHABET[((chunk[0] & 0x03) << 4) | (chunk[1] >> 4)]
            encoded_chunk += CustomBase64EncoderDecoder.ALPHABET[((chunk[1] & 0x0F) << 2) | (chunk[2] >> 6)]
            encoded_chunk += CustomBase64EncoderDecoder.PADDING_CHAR
        else:
            encoded_chunk += CustomBase64EncoderDecoder.ALPHABET[chunk[0] >> 2]
            encoded_chunk += CustomBase64EncoderDecoder.ALPHABET[((chunk[0] & 0x03) << 4) | (chunk[1] >> 4)]
            encoded_chunk += CustomBase64EncoderDecoder.ALPHABET[((chunk[1] & 0x0F) << 2) | (chunk[2] >> 6)]
            encoded_chunk += CustomBase64EncoderDecoder.ALPHABET[chunk[2] & 0x3F]

        return encoded_chunk

    @staticmethod
    def decode(base64_data):
        decoded_data = bytearray()

        lines = base64_data.split('\n')

        for line in lines:
            if line.startswith(CustomBase64EncoderDecoder.COMMENT_START_CHAR):
               continue

            line = line.rstrip('=')
            binary_data = ''
            padding = 0

            for char in line:
                if char not in CustomBase64EncoderDecoder.ALPHABET:
                    print("Помилка у частині: Ігноруємо рядок з некоректними символами.")
                    continue
                binary_data += format(CustomBase64EncoderDecoder.ALPHABET.index(char), '06b')

            if len(line) < CustomBase64EncoderDecoder.LINE_LENGTH:
               padding = (4 - (len(binary_data) % 8)) % 4

            binary_data = binary_data[:-padding] if padding > 0 else binary_data

            for i in range(0, len(binary_data), 8):
               if i + 8 <= len(binary_data):
                   byte = int(binary_data[i:i + 8], 2)
                   decoded_data.append(byte)

        return decoded_data

    @staticmethod
    def decode_chunk(chunk):
        decoded_chunk = bytearray()
        chunk = chunk.rstrip(CustomBase64EncoderDecoder.PADDING_CHAR)

        while len(chunk) % 4 != 0:
            chunk += CustomBase64EncoderDecoder.PADDING_CHAR

        if len(chunk) % 4 != 0:
            print(f"Помилка у частині: Неправильна кількість символів ({len(chunk)}).")
            return bytearray()

        if any(char not in CustomBase64EncoderDecoder.ALPHABET for char in chunk):
            print("Помилка у частині: Ігноруємо рядок з некоректними символами.")
            return bytearray()

        binary_data = ''.join(format(CustomBase64EncoderDecoder.ALPHABET.index(char), '06b') for char in chunk)

        for i in range(0, len(binary_data), 8):
            byte = int(binary_data[i:i + 8], 2)
            decoded_chunk.append(byte)

        return decoded_chunk


def main():
    if len(sys.argv) < 3:
        print("Використання: python base64.py encode input_file [output_file]")
        print("            python base64.py decode input_file [output_file]")
        sys.exit(1)

    operation = sys.argv[1]
    input_file = sys.argv[2]
    output_file = sys.argv[3] if len(sys.argv) > 3 else None

    encoder_decoder = CustomBase64EncoderDecoder()

    if operation == 'encode':
        encoder_decoder.encode_file(input_file, output_file)
    elif operation == 'decode':
        encoder_decoder.decode_file(input_file, output_file)
    else:
        print("Невідома операція. Використайте 'encode' або 'decode'.")

if __name__ == "__main__":
    main()
