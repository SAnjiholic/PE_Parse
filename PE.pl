#!/usr/bin/env perl

#my $filename = $ARGV[0];
my $filename = "Sample.exe";
open(F,"<$filename") or die("Unable to open file $filename, $!");
read(F, my $buf, 0x1000);

my $IsDosSigniture = unpack("A2",$buf); exit 1 unless $IsDosSigniture eq "MZ";
my $e_lfanew = unpack ("x60 L",$buf);
my $IsNTSignature = unpack ("x$e_lfanew A4", $buf); exit 1 unless $IsNTSignature eq "PE";
my ($machine, $NumberOfSections, $timestamp) = unpack("x$e_lfanew x4 v v V",$buf);
my ($BitMagic, $SizeOfCode, $AddressOfEntry, $BaseOfCode, $ImageBase)  = unpack("x$e_lfanew x24 v x2 V x8 V V",$buf);
#my $ImageBase = 0;
if ($BitMagic == 0x10b) {$ImageBase = unpack ("x$e_lfanew x52 V",$buf)}
elsif($BitMagic == 0x20b){
    my ($tmp1 ,$tmp2)= unpack ("x$e_lfanew x48 V2",$buf);
    $ImageBase = hex(sprintf("%08x%08x",$tmp2, $tmp1))
}
# 0x10b == 32bit
# 0x20b == 64bit
# 0x107 == rom


seek(F,$e_lfanew,0);
read (F,$buf, 0x1000);





__END__
printf ("0x%x\n",$e_lfanew);
