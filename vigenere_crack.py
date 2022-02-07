import numpy as np
import regex as re

cipher_text = open(input('Enter filename of ciphertext to crack (plain text): '), 'r').read()
cipher_text = re.sub(r'[^a-z]', '', cipher_text.lower())
freq_eng = {'a': 8.12, 'b': 1.49, 'c': 2.71, 'd': 4.32, 'e': 12.0, 'f': 2.3, 'g': 2.03, 'h': 5.92, 'i': 7.31, 'j': 0.1, 'k': 0.69, 'l': 3.98, 'm': 2.61, 'n': 6.95, 'o': 7.68, 'p': 1.82, 'q': 0.11, 'r': 6.02, 's': 6.28, 't': 9.1, 'u': 2.88, 'v': 1.11, 'w': 2.09, 'x': 0.17, 'y': 2.11, 'z': 0.07}
cipher = {'key': ''}

def shift_let(let, shift): return chr((ord(let) + shift - 97) % 26 + 97)

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
for padding in range(cipher['key_len']):
   for shift in range(26):
      # Get subsequence with padding
      subseq = cipher_text[padding::cipher['key_len']]

      # Get counts of letters after shifting with respect to the alphabet
      subseq = [shift_let(let, shift) for let in subseq]
      subseq_counts = np.array([subseq.count(let) for let in set(subseq)])
      subseq_eng_freqs = np.array([freq_eng[let] for let in set(subseq)])

      # Get analysis of frequency for this subseq
      freq_analysis = sum((subseq_counts / (len(cipher_text) / cipher['key_len'])) * subseq_eng_freqs)

      if freq_analysis > 6 and freq_analysis < 7:
         print(f'Found shift of {shift} with freq analysis of {freq_analysis / 100}')
         cipher['key'] += chr(26 - shift + 97)
         break

      if shift == 25:
         raise KeyError('Frequency not indicative of English text, or text is too short')

print(f'\nKey is: {cipher["key"]}')

# Decode cipher_text
plain_text = ''.join([shift_let(cipher_text[i], 26 - ord(cipher['key'][i % cipher['key_len']]) + 97) for i in range(len(cipher_text))])

open('output.txt', 'w').write(f'{plain_text}')