require ["fileinto"];
if size :over 1048576 { fileinto "Junk"; }