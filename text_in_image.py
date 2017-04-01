#!/usr/bin/env python3
'''
CPSC 353 - Computer Security

Project 1: Text In Image
Due: April 6, 2017
Name: Kevin Vuong

This program hides the supplied text inside of images 
and can then extract text embedded inside the image.
'''
from PIL import Image
import binascii
import sys
import argparse


def check_fit(image, text_file):
    """
    Checks if the supplied data will fit the image.
    
    Args:
        image: The image object of the PIL image.
        text_file: the text file you want to embed to the image.
    Returns:
        True: If the supplied text fits the image.
        False: If the supplied text will not fit in the image. 
    """
    # Reads the number of characters to embed
    text_file.seek(0)
    text_length = len(text_file.read())

    # Calculates the number of pixels needed, plus the 11 extra pixels to embed text length
    pixels_required = text_length*8+11

    # Calculate the number of pixels the image has
    image_width, image_height = image.size
    total_pixels = image_width * image_height

    if total_pixels < pixels_required:
        return False
    else:
        return True


def embed_text_length(image_obj, text_length):
    """
    Hides the text left in the bottom right 11 pixels of the image.
    
    Args:
        image_obj: The image object of the PIL image.
        text_length: The length of the text to be embedded.
        
    Returns:
        False: Returns False when text length is 0.
        True: Returns True when text length has successfully been embedded
    """
    if text_length == 0:
        print("Text length is 0, nothing is to be embedded")  
        return False

    img_width, img_height = image_obj.size
    text_length = text_length * 8
    for x in range(img_width - 11, img_width, 1):
        pixel = image_obj.getpixel((x, img_height-1))
        red = pixel[0]
        green = pixel[1]
        blue = pixel[2]

        index = 0
        for color in pixel:
            extracted_bit = text_length & 1
            text_length >>= 1
            if index == 0:
                green = embed_bit(color, extracted_bit)
            if index == 1:
                blue = embed_bit(color, extracted_bit)
            if index == 2:
                red = embed_bit(color, extracted_bit)

            index = index + 1

        # Place the edited pixel back into the image
        edited_pixel = (int(red), int(blue), int(green))
        image_obj.putpixel((x, img_height-1), edited_pixel)
    return True
    

def embed_bit(color, bit):
    '''
    Embeds a bit in the LSB of the color value.
    :param color: the color value (ex. red, green, or blue)
    :param bit: the bit you want to embed in the LSB of the color param
    :return: returns the color value that contains the embedded bit
    '''
    if bit == 1:
        color = color | 1
    else:
        color = color & 0b1111111111111110

    return color


def extract_text_length(image_obj):
    """
    Extracts the text length from the bottom right 11 pixels
    
    Args:
        image_obj: The image object of the PIL image.
        
    Returns:
        text_length: The text length of the supplied data
    """        
    print("\nExtracting text length")
    img_width, img_height = image_obj.size

    bit_string = ''
    for x in range(img_width-1, img_width-12, -1):
        pixel = image_obj.getpixel((x, img_height-1))

        for color in pixel:
            bit_extracted = color & 1
            print(bit_extracted, end='')
            bit_string += str(bit_extracted)

    print('')
    bit_string = bit_string[:33]
    print(bit_string)
    text_length = int(bit_string, 2)
    return text_length


def embed_text(img, text_file):
    '''
    Embeds the text from the given text file into the image.
    
    Args:
        img: The PIL image object
        text_file: the file object that contains the text to be embedded
    
    Returns:
        Nothing
    '''
    img_width, img_height = img.size

    # Extract contents of text file
    text_file.seek(0)
    contents = text_file.read().strip()

    # Strips newlines at the ends of text so we don't get "odd-string length" error
    contents = contents.strip()

    # Get the text length
    text_length = len(contents)

    # We need to embed text_length*8 bits
    bits_left = text_length * 8

    # char_pos is the current character being embedded
    char_pos = text_length-1

    # The current "bit" being examined
    count_next = 1

    # Sets initial character to start embedding
    current_char = ord(contents[char_pos])

    print("Embedding...")
    for x in range(img_width-12, -1, -1):

        pixel = img.getpixel((x, img_height-1))
        red = pixel[0]
        green = pixel[1]
        blue = pixel[2]

        if bits_left == 0:
            red = embed_bit(red, 0)
            green = embed_bit(green, 0)
            blue = embed_bit(blue, 0)

            # Put back together the pixel tuple using the new Blue value with the embedded bit
            edited_pixel = (int(red), int(green), int(blue))
            img.putpixel((x, img_height-1), edited_pixel)
            continue

        index = 0
        for color in pixel:
            if bits_left == 0:
                continue
            bits_left = bits_left - 1
            bit_extracted = current_char & 1
            current_char >>= 1

            if index == 0:
                red = embed_bit(color, bit_extracted)
            elif index == 1:
                green = embed_bit(color, bit_extracted)
            elif index == 2:
                blue = embed_bit(color, bit_extracted)

            index = index+1
            # If done embedding the current selected character, then move on to the next character
            if count_next == 8:
                count_next = 1
                char_pos = char_pos - 1
                current_char = ord(contents[char_pos])
            else:
                count_next = count_next+1

        # Put back together the pixel tuple using the new Blue value with the embedded bit
        edited_pixel = (int(red), int(green), int(blue))
        img.putpixel((x, img_height - 1), edited_pixel)

    for y in range(img_height-2, -1, -1):
        for x in range(img_width-1, -1, -1):
            pixel = img.getpixel((x, y))
            red = pixel[0]
            green = pixel[1]
            blue = pixel[2]

            if bits_left == 0:
                red = embed_bit(red, 0)
                green = embed_bit(green, 0)
                blue = embed_bit(blue, 0)

                # Put back together the pixel tuple using the new Blue value with the embedded bit
                edited_pixel = (int(red), int(green), int(blue))
                img.putpixel((x, y), edited_pixel)
                continue

            index = 0
            for color in pixel:
                if bits_left == 0:
                    continue
                bits_left = bits_left - 1
                bit_extracted = current_char & 1
                current_char >>= 1

                if index == 0:
                    red = embed_bit(color, bit_extracted)
                elif index == 1:
                    green = embed_bit(color, bit_extracted)
                elif index == 2:
                    blue = embed_bit(color, bit_extracted)

                index = index + 1
                # If done embedding the current selected character, then move on to the next character
                if count_next == 8:
                    count_next = 1
                    char_pos = char_pos - 1
                    if char_pos > -1:
                        current_char = ord(contents[char_pos])
                else:
                    count_next = count_next + 1

            edited_pixel = (int(red), int(green), int(blue))
            img.putpixel((x, y), edited_pixel)
    print("\nText Embed Completed")


def extract_text(img, num_bits):
    '''
    Extracts the text embedded inside the given image. This function does not
    extract the text length embedded.
    
    Args:
        img: The Python PIL image object
        num_bits: The number of bits to be extracted
    Returns:
        contents: The string that was embedded inside the image
    '''
    img_width, img_height = img.size
    count = 1  # Keeps track how many bits till 8 is reached (for one byte)
    temp_store = ''
    # Stores extracted text
    contents = ''
    print("Extracting...")
    print(str(num_bits))
    # Extract the text from the last line of pixels w/o extracting the text length
    for x in range(img_width-12, -1, -1):
        if num_bits == 0:
            break
        pixel = img.getpixel((x, img_height-1))

        for color in pixel:
            bit_extracted = color & 1
            temp_store = temp_store + str(bit_extracted)
            num_bits = num_bits - 1
            if count == 8:
                contents = contents + temp_store
                temp_store = ''
                count = 1
            else:
                count = count + 1
            if num_bits == 0:
                break

    # Extract the text from the remaining pixels
    for y in range(img_height-2, -1, -1):
        for x in range(img_width-1, -1, -1):
            pixel = img.getpixel((x, y))
            if num_bits == 0:
                break

            for color in pixel:
                bit_extracted = color & 1
                temp_store = temp_store + str(bit_extracted)
                num_bits = num_bits - 1
                if count == 8:
                    contents = contents + temp_store
                    temp_store = ''
                    count = 1
                else:
                    count = count + 1
                if num_bits == 0:
                    break

    contents = contents[::-1]
    n = int(contents, 2)
    contents = binascii.unhexlify('%x' % n).decode('utf-8')

    print(contents)
    return contents


def main():

    parser = argparse.ArgumentParser(description='Hides text in an image, and extract text from image')
    parser.add_argument('--it', '--input_text', help='Path to input text')
    parser.add_argument('--ip', '--input_pic', help='Path to input picture')
    parser.add_argument('--op', '--output_pic', help='Path to output picture')
    args = parser.parse_args()

    # Embed Text Operation ----------------------------------------------------------
    # Must supply input text file, the input picture to which to embed the text into,
    # AND the path to the output picture
    if args.it is not None:
        text_file = open(args.it, mode='rt', encoding='utf-8')
        text_length = len(text_file.read())

        with Image.open(args.ip) as img:
            if not check_fit(img, text_file):
                print("Error: Supplied data will not fit in the image")
                exit(1)

            embed_text_length(img, text_length)
            print(extract_text_length(img))
            embed_text(img, text_file)
            img.save(args.op, format='png', compress_level=0)
        text_file.close()

    # Text Extraction operation -------------------------------------------------------
    # Must supply path to output picture
    if args.op is not None and args.it is None and args.ip is None:
        with Image.open(args.op) as embed_img:
            text_length = extract_text_length(embed_img)
            print("\nExtracted text LENGTH is " + str(text_length))
            extract_text(embed_img, text_length)

if __name__ == "__main__":
    main()
