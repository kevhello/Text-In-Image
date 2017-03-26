# Project 1: Text In Image
CPSC 353 - Computer Security

Due: April 6, 2017

Name: Kevin Vuong

This program hides the supplied text inside of images and can then extract text embedded inside the image.

This program has a function for embedding text supplied by a text file into a supplied image.

This program also has a function for extracting text from the image.

## Installation
Requires Python 3

Requires Python's Pillow - https://python-pillow.org/

## Contents
text_in_image.py is the source code for this project and its content will be embedded inside the images.

cat1.jpg is the original non-modified image

cat2.jpg is the original non-modified image

embed1.png is the cat1.jpg but with the embedded source code text

embed2.png is the cat2.jpg but with the embedded source code text

## How to Use

### Summary of commandline arguments:
--it  Path to input text file

--ip  Path to input picture file for which you want text embedded into

--op  Path to where you want to save the embedded image file

### How to embed text into image:
Must supply the following arguments:
--it, --ip, --op (i.e. the input text, the input picture, and output picture)

Example: `python text_in_image.py --it copy.py --ip cat.jpg --op embed.png`

The example above takes the text in copy.py, embeds it into cat.jpg, and saves the cat.jpg as embed.png.

### How to extract text from image:
Must supply the following argument:
--op (i.e. the path to the picture w/ the embedded text)

Example: `python text_in_image.py --op embed.png`

The example above takes the image and extracts text from it. Outputs the text to the console.
