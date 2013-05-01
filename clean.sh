# clean my directories; prevent accidental rm -f *.py 
find ./ -iname *.pyc -exec rm -f '{}' ';'
rm -f ./zarp_debug.log
