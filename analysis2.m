pkg load image;
pkg load signal;

global crypt_exec = "./cli";
global imgPath;
imgPath = "nitt.png";
global key = "abcdefghabcdefgh";
global nonceSalsa = "abcdefgh";
global nonceXSalsa = "012345670123456701234567";
global originalDim = size(imread(imgPath)); # Will be set to dimensions of the image being used for testing

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

%% functionname: function description
function correlationPlot(imgEnc)
  global imgPath
  img = imread(imgPath);
  disp('Correlation b/w images');
  imgEnc = resize(imgEnc, size(img));
  corr2(img, imgEnc)
  corrMatrix = xcorr2(rgb2gray(img),rgb2gray(imgEnc));
  imagesc(corrMatrix);
  colormap(jet);
  colorbar;

  % mae(imgEnc);
endfunction


function entropyCalc(imgEnc)
  global imgPath
  img = imread(imgPath);
  disp("\nEntropy of original");
  entropy(img)
  disp("Entropy of encrypted image");
  entropy(imgEnc)
  disp("\n");
endfunction

# Read the encrypted image from disk
function imgEnc = readEncImg(encPath)
  global originalDim;
  fd = fopen(encPath, "r+");
  imgEnc = fread(fd);
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
  hist(imgEnc)
  colormap(jet);
  colorbar;
  mypause()
  % system(["binwalk --3D " encPath]);
  % mypause()
  entropyCalc (imgEnc);
  mypause();
  correlationPlot (imgEnc);
  mypause();
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

main(imgPath);
