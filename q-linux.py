from joern.all import JoernSteps
from py2neo.packages.httpstream import http
http.socket_timeout = 9999
j = JoernSteps()
j.setGraphDbURL('http://localhost:7474/db/data/')
j.connectToDatabase()



### The below query can detect linux bugs
query = """
getFunctionASTsByName('*_write*')
.getArguments('(copy_from_user OR memcpy)','2')
.sideEffect{paramName = 'c(ou)?nt';}
.filter{it.code.matches(paramName)}
.unsanitized(
    {it._().or(
    _().isCheck('.*'+paramName+'.*'),
    _().codeContains('.*alloc.*'+paramName+'.*'),
    _().codeContains('.*min.*')
    )}
)
.param('.*c(ou)?nt.*')
.locations()
.unique()
.sort()
"""

query2 = """
getArguments('memcpy', '2')
.filter{ !it.argToCall().toList()[0].code.matches('.*(sizeof|min).*') } 
.sideEffect{ argument = it.code; }
.sideEffect{ dstId = it.statements().toList()[0].id; }
.filter{ it.id != dstId }
.locations()
.unique()
.sort()
"""


#query = """
#getCallsTo('.*n2s.*')
#.statements()
#.out("REACHES")
#.match{it.code.contains('.*memcpy.*')}
#.locations()
#"""

#query = """
#getCallsTo('n2s').ithArguments("1")
#.statements()
#.out("REACHES")
#.match{ it.type == "CallExpression" && it.code.startsWith("memcpy")}.ithArguments("2")
#.locations()
#"""
#query = """
#getFunctionASTsByName('*_write*')
#.getArguments('(copy_from_user OR memcpy)', '2')
#.sideEffect{ paramName = 'c(ou)?nt'; }
#.filter{ it.code.matches(paramName) }
#.unsanitized( { it._().or( _().isCheck('.*' + paramName + '.*'), _().codeContains('.*alloc.*' + paramName + '.*'), _().codeContains('.*min.*') )} )
#.param( '.*c(ou)?nt.*' )
#.locations()
#"""

#query = """
#getCallsTo("malloc").ithArguments("0")
#.sideEffect{cnt = it.code }
#.match{ it.type =="AdditiveExpression"}.statements()
#.out("REACHES")
#.match{ it.type == "CallExpression" && it.code.startsWith("memcpy")}.ithArguments("2")
#.filter{it.code != cnt }
#.match{it.type == "AdditiveExpression"}
#"""

print "[+] Running query!"
results = j.runGremlinQuery(query)

print "[+] Number of results: " + str(len(results))
for r in results:
    print r
