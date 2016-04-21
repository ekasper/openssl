# A module for emitting formatted asm instructions from Perl code.
# Use this instead of here-docs for asm that is tightly interleaved with
# Perl statements. For example, instead of
#
# if ($condition) {
#     $code .= <<___;
#	add	$x,$y
# ___
# } else {
#    $code .= <<__;
#	add	$y,$x
# ___
# }
#
# you can write
#
# if ($condition) {
#    $code .= op "add", $x, $y;
# } else {
#    $code .= op "add", $y, $x;
# }
#
# The special instruction "label" can be used to emit labels:
#
# $code .= op "label", "Loop:";
# $code .= op "label, "align", 32;
#
# Perlasm files can also use the following AUTOLOAD pattern to hide $code .= op
# and buffer instructions into a global variable:
#
# use Instruction qw(:DEFAULT);
#
# sub AUTOLOAD() {
#    my $opcode = $AUTOLOAD;
#    $opcode =~ s/.*:://;  # strip package specifier.
#    $CODE .= op $opcode, @_;
# }
#
# undef $CODE; {
#     # Code between $CODE markers may be indented asm-style with tabs.
#     if ($condition) {
#        &add   ($x, $y);        # comment
#     } else {
#        &add   ($y, $x);
#        &label (".align", 32);  # tabulated comment
#     }
#
# } $code .= $CODE;

package Instruction;

use strict;
use warnings;

use Exporter;
use vars qw(@ISA @EXPORT_OK @EXPORT);
@ISA = qw(Exporter);

@EXPORT = qw(op);
 
# First argument is a numeric constant, e.g. "rol 5,%rdi".
my @instructions = qw(cmp pslld pslldq pshufd psrld psrldq rol ror shld shrd add aesdec aesdeclast aesenc aesenclast and jb je mov movaps movdqa movdqu movups paddd por pshufb psubd
                              punpcklqdq pxor vaesdec vaesenc vaesdeclast vaesenclast vmovdqa vmovdqu vmovups vpaddd vpalignr vpslld vpslldq vpshufb vpor vpsrld vpsrldq vpxor vxorps xor xorps);

my %instructions= map { $_ => 1; } @instructions;


sub op {
    my ($opcode, @args) = @_;

    if ($opcode eq "label") {
        my $name = shift @args;
        return "$name\t" . join(',', @args) . "\n";
    }

    if (!$instructions{$opcode}) {
        warn "Unknown instruction $opcode!\n";
    }

    my $arg = shift @args;
    # If the first argument is numeric, we need to prepend a $, e.g.,
    # shld $2,%r15.
    if ($arg =~ /^[0-9]+$/) {
        $arg = "\$$arg";
    }
    my $instruction = "\t$opcode\t" . join(',', $arg, @args) . "\n";
    return $instruction;
}

1;
