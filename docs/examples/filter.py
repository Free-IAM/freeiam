# start FILTER ESCAPING
from freeiam.ldap.filter import EscapeMode, Filter


user_input = ' hello (my friend), i am attacking * with \x00 or \\XX'

Filter.escape(user_input, EscapeMode.SPECIAL)  # cn=...
Filter.escape(user_input, EscapeMode.NON_ASCII)  # cn=...
Filter.escape(user_input, EscapeMode.ALL)  # cn=...

Filter.get_pres('cn')  # cn=*
Filter.get_eq('cn', user_input)  # cn=...
Filter.get_approx('cn', user_input)  # cn~=...
Filter.get_substring('cn', *user_input.split('*'))  # cn~=*
Filter.get_substring('cn', '', 'foo', '')  # cn=*foo*
Filter.get_gt_eq('uidNumber', 1000)  # cn>=1000
Filter.get_gt_eq('uidNumber', 1000)  # cn<=1000
Filter.get_extensible('cn', None, 'generalizedTimeMatch', user_input)  # cn~=*

Filter.get_and(Filter.get_eq('objectClass', 'person'), Filter.get_eq('cn', user_input))
ipv4 = '127.0.0.1'
ipv6 = '::1'
Filter.get_or(Filter.get_eq('aRecord', ipv4), Filter.get_eq('aAAARecord', ipv6))
Filter.get_not(Filter.get_eq('cn', user_input))

# end FILTER ESCAPING
# start FILTER TRANSFORMATIONS
from freeiam.ldap.filter import Filter


# end FILTER TRANSFORMATIONS
