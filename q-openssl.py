from joern.all import JoernSteps
j = JoernSteps()
j.setGraphDbURL('http://localhost:7474/db/data/')
j.connectToDatabase()

### The below query str can detect the bugs in openssl
query = """
getCallsTo('n2s').ithArguments('1')
.sideEffect{cnt = it.code}
.statements()
.out()
.statements()
.getCallsTo('memcpy').ithArguments('2')
.sideEffect{param = it.code}
.filter{param == cnt}
.filter{
    it.in('USES')
    .filter{it.type == 'Condition'}.toList() == []
}
.locations()
"""


print "[+] Running query to check bugs in openssl!"
results = j.runGremlinQuery(query)

print "[+] Number of results: " + str(len(results))
for r in results:
    print r
