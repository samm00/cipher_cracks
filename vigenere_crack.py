import numpy as np
import regex as re

cipher_text = re.sub(r'[^A-Z]', '', input('Enter ciphertext to crack: ').upper())
freq_eng = {'A': 8.12, 'B': 1.49, 'C': 2.71, 'D': 4.32, 'E': 12.0, 'F': 2.3, 'G': 2.03, 'H': 5.92, 'I': 7.31, 'J': 0.1, 'K': 0.69, 'L': 3.98, 'M': 2.61, 'N': 6.95, 'O': 7.68, 'P': 1.82, 'Q': 0.11, 'R': 6.02, 'S': 6.28, 'T': 9.1, 'U': 2.88, 'V': 1.11, 'W': 2.09, 'X': 0.17, 'Y': 2.11, 'Z': 0.07}
cipher = {'key': ''}

def shift_let(let, shift): return chr((ord(let) + shift - 65) % 26 + 65)

# Get key length
for key_len in range(1, len(cipher_text) + 1):
   # Get frequency counts of subcipher of every ith character
   subcipher = cipher_text[::key_len]
   subcipher_counts = np.array([subcipher.count(let) for let in set(subcipher)])

   # Get analysis of frequency for this key length
   freq_analysis = sum((subcipher_counts / (len(cipher_text) / key_len)) ** 2)

   if freq_analysis > 0.06 and freq_analysis < 0.07:
      print(f'\nFound key length of {key_len} with freq analysis of {freq_analysis}\n')
      cipher['key_len'] = key_len
      break

   if key_len == len(cipher_text):
      raise KeyError('Frequency not indicative of English text, or text is too short')

# Get key
for padding in range(key_len):
   for shift in range(26):
      # Get subsequence with padding
      subseq = cipher_text[padding::key_len]

      # Get counts of letters after shifting with respect to the alphabet
      subseq = [shift_let(let, shift) for let in subseq]
      subseq_counts = np.array([subseq.count(let) for let in set(subseq)])
      subseq_eng_freqs = np.array([freq_eng[let] for let in set(subseq)])

      # Get analysis of frequency for this subseq
      freq_analysis = sum((subseq_counts / (len(cipher_text) / key_len)) * subseq_eng_freqs)

      if freq_analysis > 6 and freq_analysis < 7:
         print(f'Found shift of {shift} with freq analysis of {freq_analysis / 100}')
         cipher['key'] += chr(26 - shift + 65)
         break

      if shift == 25:
         raise KeyError('Frequency not indicative of English text, or text is too short')

print(f'\nKey is: {cipher["key"]}')

# Decode cipher_text
plain_text = ''.join([shift_let(cipher_text[i], 26 - ord(cipher['key'][i % cipher['key_len']]) + 65) for i in range(len(cipher_text))])

print(f'\n{plain_text}')