#!/usr/bin/env python3
'''
CPSC 353 - Computer Security

Project 1: Text In Image
Due: April 6, 2017
Name: Kevin Vuong

This program hides the supplied text inside of images 
and can the extract text embedded inside the image.
'''
from PIL import Image
import binascii
import sys


def is_fit(image, textFile):
    """
    Checks if the supplied data will fit the image.
    
    Args:
        image: The image object of the PIL image
        
    Returns:
        Returns True if the supplied data fits the image, otherwise
        returns False.
    """
    textLength = len(f.read()) # Reads the number of characters
    pixelsRequired = textLength*8+11  # Calculates the number of pixels needed
    
    imageWidth, imageHeight = image.size()
    totalPixels = imageWidth * imageHeight
    
    if totalPixels < pixelsRequired:
        return False
    else:
        return True

def embed_text_length(imageObj, textLength):
    """
    Hides the text left in the bottom right 11 pixels of the image.
    
    Args:
        image: The image object of the PIL image.
        textLength: The length of the text to be embedded.
        
    Returns:
        False: Returns False when text length is 0.
        True: Returns True when text length has successfully been embedded
    """    
    if textLength == 0:
        print("Text length is 0, nothing is to be embedded")  
        return False
    
    imgWidth, imgHeight = imageObj.size
    
    for x in range(imgWidth-1, imgWidth-12,-1):

        pixel = imageObj.getpixel((x, imgHeight-1))
        red = pixel[0]
        green = pixel[1]
        blue = pixel[2]        
        
        if textLength == 0:             # Make the rest of the pixel's LSB set to 0 after the text length has been embedded
            red = red & 0b1111111111111110
            green = green & 0b1111111111111110
            blue = blue & 0b1111111111111110
            
            edited_pixel = (int(red), int(green), int(blue)) # Put back together the pixel tuple using the new Blue value with the embedded bit
            imageObj.putpixel((x, imgHeight-1), edited_pixel)            
            continue
        
        bit_extracted = textLength & 1  # Extract LSB of text length integer

        textLength >>= 1                # Binary shift right the text length by one to extract the next LSB in the next iteration
        
        #if bit_extracted == (blue & 1): # The LSB from text length is the same as the LSB of the value of Blue -> no embedding necessary
        #    continue

        if bit_extracted == 1:
            red = red | 1
            green = green | 1
            blue = blue | 1
        else:
            red = red & 0b1111111111111110
            green = green & 0b1111111111111110            
            blue = blue & 0b1111111111111110

        edited_pixel = (int(red), int(green), int(blue)) # Put back together the pixel tuple using the new Blue value with the embedded bit
        imageObj.putpixel((x, imgHeight-1), edited_pixel)
        
    return True
    
    
    
def extract_text_Length(imageObj):
    """
    Extracts the text length from the bottom right 11 pixels
    
    Args:
        imageObj: The image object of the PIL image.
        
    Returns:
        textLength: The text length of the supplied data
    """        
    imgWidth, imgHeight = imageObj.size
    textLength = 0
    count = 0    # count will determine how much to shift the mask, allowing the extracted bit to be placed in its appropriate location
    
    for x in range(imgWidth-1, imgWidth-12, -1):
            
        pixel = imageObj.getpixel((x, imgHeight-1))
        blue = pixel[2]
        
        bit_extracted = blue & 1
        bit_extracted <<= count    
        count = count + 1
        
        if bit_extracted != 0:
            textLength = textLength | bit_extracted
       
    return textLength



def embed_text(img, textFile, text_length):
    '''
    Embeds the text from the given text file into the image.
    
    Args:
        img: The PIL image object
        textFile: the file object that contains the text to be embedded
        text_length: the number of characters to be embedded
    
    Returns:
        Nothing
    '''
    imgWidth, imgHeight = img.size
    bits_left = text_length*8
    textFile.seek(0)
    contents = textFile.read()
    char_pos = text_length-1
    count_next = 1
    current_char = ord(contents[char_pos]) # Sets initial character to start embedding
    
    for x in range(imgWidth-13, -1, -1):
        pixel = img.getpixel((x, imgHeight-1))
        red = pixel[0]
        green = pixel[1]
        blue = pixel[2]

        bits_left = bits_left - 1
        if bits_left == 0:
            
            red = red & 0b1111111111111110
            green = green & 0b1111111111111110
            blue = blue & 0b1111111111111110

            edited_pixel = (int(red), int(green), int(blue)) # Put back together the pixel tuple using the new Blue value with the embedded bit
            img.putpixel((x, imgHeight-1), edited_pixel)            
            if count_next == 8:
                count_next = 1
                char_pos = char_pos - 1
                current_char = ord(contents[char_pos])
            else:
                count_next = count_next+1
                continue
        
        bit_extracted = current_char & 1
        current_char >>= 1
        
        if bit_extracted == (red & 1) | bit_extracted == (green & 1) | bit_extracted == (blue & 1):
            pass
        else:
            if bit_extracted == 1:
                red = red | 1
                green = green | 1
                blue = blue | 1
            else:
                red = red & 0b1111111111111110
                green = green & 0b1111111111111110
                blue = blue & 0b1111111111111110
    
            edited_pixel = (int(red), int(green), int(blue)) # Put back together the pixel tuple using the new Blue value with the embedded bit
            img.putpixel((x, imgHeight-1), edited_pixel)        
            
        
        if count_next == 8:
            count_next = 1
            char_pos = char_pos - 1
            current_char = ord(contents[char_pos])
        else:
            count_next = count_next+1
    
    for y in range(imgHeight-2, -1, -1):
        for x in range(imgWidth-1, -1, -1):
                pixel = img.getpixel((x, y))
                red = pixel[0]
                green = pixel[1]
                blue = pixel[2]
        
                bits_left = bits_left - 1
                if bits_left == 0:
                    
                    red = red & 0b1111111111111110
                    green = green & 0b1111111111111110
                    blue = blue & 0b1111111111111110

                    edited_pixel = (int(red), int(green), int(blue)) # Put back together the pixel tuple using the new Blue value with the embedded bit
                    img.putpixel((x, y), edited_pixel)            
                    if count_next == 8:
                        count_next = 1
                    else:
                        count_next = count_next+1
                        continue
                
                bit_extracted = current_char & 1
                current_char >>= 1
                
                if bit_extracted == (red & 1) | bit_extracted == (green & 1) | bit_extracted == (blue & 1):
                    pass
                else:
                    if bit_extracted == 1:
                        red = red | 1
                        green = green | 1
                        blue = blue | 1
                    else:
                        red = red & 0b1111111111111110
                        green = green & 0b1111111111111110
                        blue = blue & 0b1111111111111110
            
                    edited_pixel = (int(red), int(green), int(blue)) # Put back together the pixel tuple using the new Blue value with the embedded bit
                    img.putpixel((x, y), edited_pixel)        
                    
                
                if count_next == 8:
                    count_next = 1
                    char_pos = char_pos - 1
                    if char_pos >= 0:
                        current_char = ord(contents[char_pos])
                else:
                    count_next = count_next+1



def extract_text(img):
    '''
    Extracts the text embedded inside the given image. This function does not
    extract the text length embedded.
    
    Args:
        img: The Python PIL image object
        
    Returns:
        contents: The string that was embedded inside the image
    '''
    imgWidth, imgHeight = img.size
    char = 0      # Stores extracted character, note: will have to convert this integer to char and append to resulting string
    contents = '' # Stores extracted text
    count = 0
    
    # Extract the text from the last line of pixels w/o extracting the text length
    for x in range(imgWidth-13, -1, -1):
        pixel = img.getpixel((x, imgHeight-1))
        blue = pixel[2]
        
        bit_extracted = blue & 1
        contents = contents + bin(bit_extracted)[2:]
    
    # Extract the text from the remaining pixels
    for y in range(imgHeight-2, -1, -1):
        for x in range(imgWidth-1, -1, -1):
            pixel = img.getpixel((x, y))
            blue = pixel[2]
            
            bit_extracted = blue & 1
            contents = contents + bin(bit_extracted)[2:]         
        
    contents = contents[::-1] # Reverse for correct string order
    n = int(contents, 2)
    contents = binascii.unhexlify('%x' % n).decode('utf-8')
    print(contents)
    return contents


def main():
    textFile = open("copy.py", mode='rt', encoding='utf-8')
    text_length = len(textFile.read())

    if not is_fit:
        print("Error: Supplied data will not fit in the image")
        exit(1)
    
    with Image.open("cat.jpg") as img:

        embed_text_length(img, text_length)
        
        extract_text_Length(img)

        embed_text(img, textFile, text_length)

        extract_text(img)
        
        img.save('embed.png', format='png', compress_level=0)
        
    textFile.close()
    
    
if __name__ == "__main__":
    main()