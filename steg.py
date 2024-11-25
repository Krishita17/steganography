#!/usr/bin/env python
# coding: utf-8

import numpy as np
import cv2
import wave
import os

# Utility Functions
def binary_to_decimal(binary):
    return int(binary, 2)

def msg_to_binary(msg):
    if isinstance(msg, str):
        return ''.join([format(ord(i), "08b") for i in msg])
    elif isinstance(msg, bytes) or isinstance(msg, np.ndarray):
        return [format(i, "08b") for i in msg]
    elif isinstance(msg, int) or isinstance(msg, np.uint8):
        return format(msg, "08b")
    else:
        raise TypeError("Unsupported input type for binary conversion.")

# Text Steganography
def encode_text_to_file():
    cover_file = "Sample_cover_files/cover_text.txt"
    if not os.path.exists(cover_file):
        print("Cover text file not found.")
        return

    with open(cover_file, "r") as file:
        words = file.read().split()

    max_capacity = len(words) // 6
    print(f"Maximum number of words that can be used for encoding: {max_capacity}")
    
    data = input("Enter the text to encode: ")
    if len(data) > max_capacity:
        print("Data exceeds encoding capacity. Reduce the message length.")
        return

    binary_data = ''.join([f"0110{msg_to_binary(ch)}" if ch.isdigit() else f"0011{msg_to_binary(ch)}" for ch in data])
    binary_data += "111111111111"  # End of message marker
    zwc = {"00": u'\u200C', "01": u'\u202C', "11": u'\u202D', "10": u'\u200E'}

    encoded_words = []
    for i, word in enumerate(words):
        if i * 12 < len(binary_data):
            encoded_word = word + ''.join(zwc[binary_data[j:j+2]] for j in range(i * 12, min(len(binary_data), (i + 1) * 12), 2))
            encoded_words.append(encoded_word)
        else:
            encoded_words.append(word)

    output_file = input("Enter the name of the output file (with extension): ")
    with open(output_file, "w", encoding="utf-8") as file:
        file.write(" ".join(encoded_words))
    
    print("Text encoding completed and saved to", output_file)

def decode_text_from_file():
    stego_file = input("Enter the name of the file to decode (with extension): ")
    if not os.path.exists(stego_file):
        print("Stego file not found.")
        return
    
    zwc_reverse = {u'\u200C': "00", u'\u202C': "01", u'\u202D': "11", u'\u200E': "10"}
    binary_data = ""
    with open(stego_file, "r", encoding="utf-8") as file:
        for word in file.read().split():
            binary_data += ''.join(zwc_reverse.get(ch, "") for ch in word if ch in zwc_reverse)
    
    if "111111111111" not in binary_data:
        print("No encoded message found.")
        return
    
    binary_data = binary_data.split("111111111111")[0]
    decoded_message = ""
    for i in range(0, len(binary_data), 12):
        prefix, data = binary_data[i:i+4], binary_data[i+4:i+12]
        if prefix == "0110":
            decoded_message += chr(binary_to_decimal(data) ^ 170 + 48)
        elif prefix == "0011":
            decoded_message += chr(binary_to_decimal(data) ^ 170 - 48)
    
    print("Decoded text message:", decoded_message)

# Image Steganography
def encode_image():
    image_path = input("Enter the path of the image: ")
    if not os.path.exists(image_path):
        print("Image file not found.")
        return
    
    img = cv2.imread(image_path)
    data = input("Enter the text to encode in the image: ") + "*^*^*"
    binary_data = msg_to_binary(data)
    
    if len(binary_data) > img.size * 3:
        print("Data exceeds image capacity.")
        return

    index = 0
    for row in img:
        for pixel in row:
            for channel in range(3):
                if index < len(binary_data):
                    pixel[channel] = int(msg_to_binary(pixel[channel])[:-1] + binary_data[index], 2)
                    index += 1

    output_image = input("Enter the name of the output image file (with extension): ")
    cv2.imwrite(output_image, img)
    print("Image encoding completed and saved to", output_image)

def decode_image():
    image_path = input("Enter the path of the image to decode: ")
    if not os.path.exists(image_path):
        print("Image file not found.")
        return

    img = cv2.imread(image_path)
    binary_data = ""
    for row in img:
        for pixel in row:
            for channel in range(3):
                binary_data += msg_to_binary(pixel[channel])[-1]

    all_bytes = [binary_data[i:i+8] for i in range(0, len(binary_data), 8)]
    decoded_data = ""
    for byte in all_bytes:
        decoded_data += chr(int(byte, 2))
        if decoded_data.endswith("*^*^*"):
            print("Decoded text message:", decoded_data[:-5])
            return
    
    print("No encoded message found in the image.")

# Audio Steganography
def encode_audio():
    audio_path = input("Enter the path of the audio file: ")
    if not os.path.exists(audio_path):
        print("Audio file not found.")
        return
    
    song = wave.open(audio_path, mode='rb')
    frame_bytes = bytearray(song.readframes(song.getnframes()))
    data = input("Enter the text to encode in the audio: ") + "*^*^*"
    binary_data = msg_to_binary(data)
    
    if len(binary_data) > len(frame_bytes):
        print("Data exceeds audio capacity.")
        return

    for i, bit in enumerate(binary_data):
        frame_bytes[i] = (frame_bytes[i] & 254) | int(bit)

    output_audio = input("Enter the name of the output audio file (with extension): ")
    with wave.open(output_audio, 'wb') as fd:
        fd.setparams(song.getparams())
        fd.writeframes(frame_bytes)
    
    print("Audio encoding completed and saved to", output_audio)

def decode_audio():
    audio_path = input("Enter the path of the audio file to decode: ")
    if not os.path.exists(audio_path):
        print("Audio file not found.")
        return
    
    song = wave.open(audio_path, mode='rb')
    frame_bytes = bytearray(song.readframes(song.getnframes()))
    binary_data = "".join([str(frame_bytes[i] & 1) for i in range(len(frame_bytes))])
    all_bytes = [binary_data[i:i+8] for i in range(0, len(binary_data), 8)]
    decoded_data = ""
    
    for byte in all_bytes:
        decoded_data += chr(int(byte, 2))
        if decoded_data.endswith("*^*^*"):
            print("Decoded text message:", decoded_data[:-5])
            return
    
    print("No encoded message found in the audio.")

# Main Function
def main():
    while True:
        print("\nSteganography Program")
        print("1. Text Steganography")
        print("2. Image Steganography")
        print("3. Audio Steganography")
        print("4. Exit")
        choice = int(input("Enter your choice: "))
        
        if choice == 1:
            print("\nText Steganography")
            print("1. Encode")
            print("2. Decode")
            sub_choice = int(input("Enter your choice: "))
            if sub_choice == 1:
                encode_text_to_file()
            elif sub_choice == 2:
                decode_text_from_file()
            else:
                print("Invalid choice.")
        
        elif choice == 2:
            print("\nImage Steganography")
            print("1. Encode")
            print("2. Decode")
            sub_choice = int(input("Enter your choice: "))
            if sub_choice == 1:
                encode_image()
            elif sub_choice == 2:
                decode_image()
            else:
                print("Invalid choice.")
        
        elif choice == 3:
            print("\nAudio Steganography")
            print("1. Encode")
            print("2. Decode")
            sub_choice = int(input("Enter your choice: "))
            if sub_choice == 1:
                encode_audio()
            elif sub_choice == 2:
                decode_audio()
            else:
                print("Invalid choice.")
        
        elif choice == 4:
            print("Exiting the program.")
            break
        
        else:
            print("Invalid choice.")

if __name__ == "__main__":
    main()
