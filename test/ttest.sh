#!/bin/bash

# Adapted from SHC's test/ttest.sh
# Tests rshc across multiple shells and option combinations

shells=('/bin/sh' '/bin/dash' '/bin/bash' '/bin/ash' '/bin/ksh' '/bin/zsh' '/usr/bin/tcsh' '/bin/csh' '/usr/bin/rc')
## Install (Debian/Ubuntu): sudo apt install dash bash ash ksh zsh tcsh csh rc

check_opts=('' '-r' '-v' '-D' '-S')

rshc=${1-rshc}

txtred='\e[0;31m' # Red
txtgrn='\e[0;32m' # Green
txtrst='\e[0m'    # Text Reset

stat=0
pc=0
fc=0
sc=0
echo
echo "== Running tests ..."
for shell in ${shells[@]}; do
    if [ ! -x "$shell" ]; then
        echo    "===================================================="
        echo -e "=== $shell: ${txtrst}SKIPPED (not found)${txtrst}"
        echo    "===================================================="
        ((sc++))
        continue
    fi
    for opt in "${check_opts[@]}"; do
        tmpd=$(mktemp -d)
        tmpf="$tmpd/test.$(basename $shell)"
        echo '#!'"$shell
        echo 'Hello World fp:'\$1 sp:\$2
        " > "$tmpf"
        "$rshc" $opt -f "$tmpf" -o "$tmpd/a.out" 2>/dev/null
        out=$("$tmpd/a.out" first second 2>/dev/null)
        #~ echo "  Output: $out"
        if [[ "$out" = 'Hello World fp:first sp:second' ]]; then
            echo    "===================================================="
            echo -e "=== $shell [with rshc $opt]: ${txtgrn}PASSED${txtrst}"
            echo    "===================================================="
            ((pc++))
        else
            echo    "===================================================="
            echo -e "=== $shell [with rshc $opt]: ${txtred}FAILED${txtrst}"
            echo    "===================================================="
            stat=1
            ((fc++))
        fi
        rm -r "$tmpd"
    done
done

echo
echo "Test Summary"
echo "------------"

if ((pc>0)); then
    pt="${txtgrn}PASSED${txtrst}"
else
    pt="PASSED"
fi

if ((fc>0)); then
    ft="${txtred}FAILED${txtrst}"
else
    ft="FAILED"
fi

echo -e "$pt: $pc"
echo -e "$ft: $fc"
echo "SKIPPED: $sc"
echo "------------"
echo

exit $stat
