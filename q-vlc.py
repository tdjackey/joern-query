from joern.all import JoernSteps
j = JoernSteps()
j.setGraphDbURL('http://localhost:7474/db/data/')
j.connectToDatabase()

### The below query can detect the overflow in VLC
#Get calls to malloc where first argument contains and additive expression and a call to memcpy is reached by data flow where the third argument also contains an additive expression and the two additive expression are not equal

query = """
getCallsTo("malloc").ithArguments("0")
.sideEffect{cnt = it.code }
.match{ it.type =="AdditiveExpression"}.statements()
.out("REACHES")
.match{ it.type == "CallExpression" && it.code.startsWith("memcpy")}.ithArguments("2")
.filter{it.code != cnt }
.match{it.type == "AdditiveExpression"}
.locations()
.unique()
.sort()
"""

print "[+] Running query to detect overflow vulnerabilities in VLC player!"
results = j.runGremlinQuery(query)

print "[+] Number of results: " + str(len(results))
for r in results:
    print r


#query = """
#getFunctionASTsByName('*_write*')
#.getArguments('(copy_from_user OR memcpy)', '2')
#.sideEffect{ paramName = 'c(ou)?nt'; }
#.filter{ it.code.matches(paramName) }
#.unsanitized( { it._().or( _().isCheck('.*' + paramName + '.*'), _().codeContains('.*alloc.*' + paramName + '.*'), _().codeContains('.*min.*') )} )
#.param( '.*c(ou)?nt.*' )
#.locations()
#"""



