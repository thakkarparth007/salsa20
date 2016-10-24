pkg load image;

global crypt_exec = "./salsa20/cli";
global key = "abcdefghabcdefgh";
global nonceSalsa = "abcdefgh";
global nonceXSalsa = "012345670123456701234567";
global originalDim = []; # Will be set to dimensions of the image being used for testing

# Utility to display plots and images
function mypause
  disp("To continue, press enter");
  pause();
endfunction

# Show image and histogram
function showImageAndHist(img)
  imshow(img);
  mypause();
  imhist(img);
  mypause();
endfunction

# Read the encrypted image from disk
function imgEnc = readEncImg(encPath)
  global originalDim;

  fd = fopen(encPath, "r+");
  imgEnc = fread(fd, originalDim, "uint8=>uint8");
  fclose(fd);
endfunction

# Helper for visual tests
function runVisualTest(imgPath, algo, nonce, rounds)
  global crypt_exec;
  global key;

  disp(["Running visual test for Algo=" algo " for " rounds " rounds"]);
  
  inPath = [imgPath ".dat"];
  outPath = [imgPath ".dat.enc." algo "." rounds]
  
  # Run the encryption algorithm
  system([crypt_exec " " algo " " key " " nonce " " rounds " < " inPath " > " outPath]);
  
  imgEnc = readEncImg(outPath);
  showImageAndHist(imgEnc);
endfunction

# Main function that handles visual tests
function visualTests(imgPath)
  global nonceSalsa;
  global nonceXSalsa;
  
  runVisualTest(imgPath, "salsa", nonceSalsa, "8");
  runVisualTest(imgPath, "salsa", nonceSalsa, "12");
  runVisualTest(imgPath, "salsa", nonceSalsa, "20");

  nonceXSalsa  
  runVisualTest(imgPath, "xsalsa", nonceXSalsa, "8");
  runVisualTest(imgPath, "xsalsa", nonceXSalsa, "12");
  runVisualTest(imgPath, "xsalsa", nonceXSalsa, "20");
endfunction

function main(_imgPath)
  global originalDim;
  imgPath = _imgPath;
  img = imread(imgPath);
  
  originalDim = size(img);
  
  # Show the image
  imshow(img);
  mypause();
  
  # Show its histogram
  imhist(img)
  mypause();
  
  # write the image matrix to file
  fd = fopen([imgPath ".dat"], "w+");
  fwrite(fd, img, "uint8");
  fclose(fd);
  
  visualTests(imgPath);
  
endfunction

main("scoobydoo_bkground.jpg");
