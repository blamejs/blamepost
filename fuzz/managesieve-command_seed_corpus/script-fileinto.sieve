require ["fileinto"];
if header :contains "X-Category" "spammy" { fileinto "Junk"; }