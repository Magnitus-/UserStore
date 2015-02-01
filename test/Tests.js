//Copyright (c) 2015 Eric Vallee <eric_vallee2003@yahoo.ca>
//MIT License: https://raw.githubusercontent.com/Magnitus-/UserStore/master/License.txt

var MongoDB = require('mongodb');
var UserStore = require('../lib/UserStore');
var Bcrypt = require('bcrypt');
var Nimble = require('nimble');

var Context = {};
var RandomIdentifier = 'UserStoreTestDB'+Math.random().toString(36).slice(-8);

exports.DefaultHash = {
    'Test': function(Test) {
        Test.expect(3);
        var Verify = UserStore.prototype.UnitTests.GenerateVerifyFunction(100,10000);
        var Hash = UserStore.prototype.UnitTests.GenerateHashFunction(100,10000);
        Hash('Test', function(Err, TestHash) {
            Hash('Test', function(Err, TestHash2) {
                Test.ok((TestHash!=TestHash2) && (TestHash.substring(35) != TestHash2.substring(35)), "Confirming that hashing function generates distinct hashes with same password due to salting.");
                Verify('Test', TestHash, function(Err, Result1) {
                    Verify('Test', TestHash2, function(Err, Result2) {
                        Test.ok(Result1&&Result2, "Confirming that verify matches a previously hashed password with its original plaintext value.");
                        Verify('Testing', TestHash, function(Err, ResultFalse) {
                            Test.ok(!ResultFalse, "Confirming that verify doesn't match a previously hashed password with a different plaintext password.");
                            Test.done();
                        });
                    });
                });
  
            });
        });
    }
}

exports.EnsureDependencies = {
    'setUp': function(Callback) {
        MongoDB.MongoClient.connect("mongodb://localhost:27017/"+RandomIdentifier, {native_parser:true}, function(Err, DB) {
            if(Err)
            {
                console.log(Err);
            }
            Context['DB'] = DB;
            Context['CollectionName'] = 'Users';
            Callback();
        });
    },
    'tearDown': function(Callback) {
        Context.DB.dropDatabase(function(Err, Result) {
            if(Err)
            {
                console.log(Err);
            }
            Context.DB.close();
            Context['DB'] = null;
            Context['DependenciesOk'] = false;
            Callback();
        });
    },
    'TestBasic': function(Test) {
        Test.expect(4);
        Context['DependenciesOk'] = true;
        UserStore.prototype.UnitTests.EnsureDependencies.call(Context, null, function(Err) {
            Context['DB'].collectionNames(Context['CollectionName'], {'namesOnly': true} ,function(Err, Collections) {
                Test.ok(Collections.length==0, "Confirming that no dependencies are created if dependencies as flagged as ok.");
                Context['DependenciesOk'] = false;
                UserStore.prototype.UnitTests.EnsureDependencies.call(Context, null, function(Err) {
                    Context['DB'].collectionNames(Context['CollectionName'], {'namesOnly': true} ,function(Err, Collections) {
                        Test.ok(Collections.length==1, "Confirming that collection dependency is created if dependencies are flagged as not ok.");
                        Test.ok(Context['DependenciesOk'], "Confirming that creating dependencies flag dependencies as ok.");
                        Context['DependenciesOk'] = false;
                        UserStore.prototype.UnitTests.EnsureDependencies.call(Context, null, function(Err) {
                            Test.ok(!Err, "Confirming that creating dependencies when they are already there doesn't create an error condition.");
                            Test.done();
                        });
                    });
                });
            });
        });
    },
    'TestIndices': function(Test) {
        Test.expect(2);
        Context['DependenciesOk'] = false;
        UserStore.prototype.UnitTests.EnsureDependencies.call(Context, [{'Fields': {'Username': 1}, 'Options': {'unique': 1}}, {'Fields': {'FirstName': 1, 'LastName': 1}, 'Options': {'unique': 1, 'sparse': 1}}], function(Err) {
            Test.ok(!Err, "Confirming that normal usage doesn't generate an error condition.");
            Context['DB'].collection(Context['CollectionName'], function(Err, UsersCollection) {
                UsersCollection.indexInformation({full:true}, function(err, IndexInformation) {
                    var Index1Created = IndexInformation.some(function(Item, Index, List) {
                        return(('Username' in Item['key'])&&Item['unique']);
                    });
                    var Index2Created = IndexInformation.some(function(Item, Index, List) {
                        return(('FirstName' in Item['key'])&&('LastName' in Item['key'])&&Item['unique']&&('sparse' in Item)&&Item['sparse']);
                    });
                    Test.ok(Index1Created&&Index2Created, "Confirming that indexes are properly created");
                    Test.done();
                });
            });
        });
    }
}

exports.EnforceNotNull = {
    'setUp': function(Callback) {
        Callback();
    },
    'tearDown': function(Callback) {
        Context['NotNull'] = [];
        Callback();
    },
    'Test': function(Test) {
        Test.expect(4);
        Context['NotNull'] = ['FirstName', 'LastName'];
        var EnforceNotNull = UserStore.prototype.UnitTests.EnforceNotNull;
        Test.ok(!EnforceNotNull.call(Context, {}), "Confirming that non null dependencies are flaged as not met in an empty object");
        Test.ok(EnforceNotNull.call(Context, {'FirstName': false, 'LastName': false})&&EnforceNotNull.call(Context, {'FirstName': 0, 'LastName': 0}), "Confirming that falsey values that aren't null or undefined are flagged as not null.");
        Test.ok((!EnforceNotNull.call(Context, {'FirstName': 'b'}))&&(!EnforceNotNull.call(Context, {'LastName': 'a'})), "Confirming that falsey values that not null requirement is enforced for all specified fields.");
        Test.ok(EnforceNotNull.call(Context, {'FirstName': 'Fake', 'LastName': 'Name'}), "Confirming that usual case works.");
        Test.done();
    }
};

var HandleError = UserStore.prototype.UnitTests.HandleError;

function BcryptHash(Password, Callback)
{
    Bcrypt.genSalt(10, function(Err, Salt) {
        HandleError(Err, Callback, function() {
            Bcrypt.hash(Password, Salt, function(Err, Hash) {
                Callback(Err, Hash);
            });
        });
    });
}

function BcryptVerify(Password, Hash, Callback)
{
    Bcrypt.compare(Password, Hash, function(Err, Result) {
        Callback(Err, Result);
    });
}

function TestPassword(Test, Store)
{
    Store.Add({'FirstName': 'Fake', 'LastName': 'FakeToo', 'Email': 'Fake@email.com', 'Password': 'FakeAgain'}, function(Err, Result) {
        Store.Get({'FirstName': 'Fake', 'LastName': 'FakeToo', 'Password': ''}, function(Err, Result) {
            Test.ok((!Err)&&Result==null, "Confirming that empty password is no match for get");
            Store.Get({'FirstName': 'NonExistent', 'LastName': 'NonExistent', 'Email': 'NonExistent', 'Password': 'NonExistent'}, function(Err, Result) {
                Test.ok((!Err)&&Result==null, "Confirming that non-existent users are still handled properly with passwords");
                Store.Remove({'FirstName': 'Fake', 'LastName': 'FakeToo', 'Password': 'Wrong'}, function(Err, Result) {
                    Test.ok(Result==0, "Confirming that removes are not executed with the wrong password");
                    Store.Update({'FirstName': 'Fake', 'LastName': 'FakeToo', 'Password': 'WrongToo'}, {'SomeField': 'Hello world!'}, function(Err, Result) {
                        Test.ok(Result==0, "Confirming that updates are not executed with the wrong password");
                        Store.Get({'FirstName': 'Fake', 'LastName': 'FakeToo', 'Password': 'FakeAgain'}, function(Err, Result) {
                            Test.ok(Result, "Confirming that Get with the right password works.");
                            Store.Update({'FirstName': 'Fake', 'LastName': 'FakeToo', 'Password': 'FakeAgain'}, {'Password': 'FakeAgain2'}, function(Err, Result) {
                                Test.ok(Result==1, "Confirming that updates are executed with the right password");
                                Store.Get({'FirstName': 'Fake', 'LastName': 'FakeToo', 'Password': 'FakeAgain2'}, function(Err, Result) {
                                    Test.ok(Result, "Confirming that updating password works.");
                                    Store.Remove({'FirstName': 'Fake', 'LastName': 'FakeToo', 'Password': 'FakeAgain2'}, function(Err, Result) {
                                        Test.ok(Result==1, "Confirming that removing with the right password works.");
                                        Test.done();
                                    });
                                });
                            })
                        });
                    });
                });
            });
        });
    });
}

exports.UserStore = {
    'setUp': function(Callback) {
        MongoDB.MongoClient.connect("mongodb://localhost:27017/"+RandomIdentifier, {native_parser:true}, function(Err, DB) {
            if(Err)
            {
                console.log(Err);
            }
            Context['DB'] = DB;
            Callback();
        });
    },
    'tearDown': function(Callback) {
        Context.DB.dropDatabase(function(Err, Result) {
            if(Err)
            {
                console.log(Err);
            }
            Context.DB.close();
            Context['DB'] = null;
            Callback();
        });
    },
    'TestMinimalistic': function(Test) {
        Test.expect(17);
        UserStore(Context['DB'], {}, function(Err, Store) {
            Context['DB'].collection('Users', function(Err, UsersCollection) {
                Nimble.series([
                function(Callback) {
                    Store.Add({'FirstName': 'Fake', 'LastName': 'Name'}, function(Err, Result) {
                        Test.ok(Result.length==1, "Confirming that insertion of first element works.");
                        Callback();
                    });
                },
                function(Callback) {
                    Store.Get({'FirstName': 'Fake', 'LastName': 'Name'}, function(Err, Result) {
                        Test.ok(Result['FirstName']=='Fake' && Result['LastName']=='Name', "Confirming that get on first element works.");
                        Callback();
                    });
                },
                function(Callback) {
                    Store.Add({'FirstName': 'Fake2', 'LastName': 'Name2'}, function(Err, Result) {
                        Test.ok(Result.length==1, "Confirming that insertion of subsequent elements works.");
                        Callback();
                    });

                },
                function(Callback) {
                    Store.Get({'FirstName': 'Fake2'}, function(Err, Result) {
                        Test.ok(Result['FirstName']=='Fake2' && Result['LastName']=='Name2', "Confirming that get on subsequent elements works.");
                        Callback();
                    });
                },
                function(Callback) {
                    Store.Get({'FirstName': 'NonExistent'}, function(Err, Result) {
                        Test.ok(Result===null, "Confirming that getting non-existent users returns null.");
                        Callback();
                    });
                },
                function(Callback) {
                    Store.Remove({'FirstName': 'NonExistent'}, function(Err, RemovedAmount) {
                        Store.Get({'FirstName': 'Fake', 'LastName': 'Name'}, function(Err, Result1) {
                            Store.Get({'FirstName': 'Fake2', 'LastName': 'Name2'}, function(Err, Result2) {
                                Test.ok(RemovedAmount==0&&Result1&&Result2, "Confirming that removing non-existent users doesn't remove any.");
                                Callback();
                            });
                        });
                    });
                },
                function(Callback) {
                    Store.Remove({'FirstName': 'Fake'}, function(Err, RemovedAmount) {
                        Store.Get({'FirstName': 'Fake', 'LastName': 'Name'}, function(Err, Result) {
                            Test.ok(RemovedAmount==1&&Result===null, "Confirming that removing an element works.");
                            Callback();
                        });
                    });
                },
                function(Callback) {
                    Store.Remove({'FirstName': 'Fake2'}, function(Err, RemovedAmount) {
                        Store.Get({'FirstName': 'Fake2', 'LastName': 'Name2'}, function(Err, Result) {
                            Test.ok(RemovedAmount==1&&Result===null, "Confirming that removing last element works.");
                            Callback();
                        });
                    });
                },
                function(Callback) {
                    Store.Add({'FirstName': 'Fake', 'LastName': 'Name'}, function(Err, Result) {
                        Store.Update({'FirstName': 'Fake'}, {'LastName': 'Fake', 'Email': 'FakeToo'}, function(Err, Result) {
                            Test.ok(Result==1, "Confirming that update took place.");
                            Store.Get({'FirstName': 'Fake', 'LastName': 'Fake', 'Email': 'FakeToo'}, function(Err, Result) {
                                Test.ok(Result, "Confirming that the right fields got updated.");
                                Callback();
                            });
                        });
                    });
                },
                function(Callback) {
                    Store.Get({'FirstName': 'Fake', 'LastName': 'Fake', 'Email': 'FakeToo'}, function(Err, Result) {
                        Test.ok(Result['Memberships'] && Result['Memberships'].length==0, "Confirming that membership array is created by default");
                        Store.AddMembership({'FirstName': 'Fake', 'LastName': 'Fake'}, 'Suspended', function(Err, Result) {
                            Test.ok(Result==1, "Confirming that update took place.");
                            Store.Get({'FirstName': 'Fake', 'LastName': 'Fake', 'Email': 'FakeToo'}, function(Err, Result) {
                                Test.ok(Result['Memberships'][0]=='Suspended', "Confirming that the right fields got updated.");
                                Store.AddMembership({'FirstName': 'Fake', 'LastName': 'Fake'}, 'Suspended', function(Err, Result) {
                                    Store.Get({'FirstName': 'Fake', 'LastName': 'Fake', 'Email': 'FakeToo'}, function(Err, Result) {
                                        Test.ok(Result['Memberships'].length==1 && Result['Memberships'][0]=='Suspended', "Confirming that membership array works as a set.");
                                        Store.AddMembership({'FirstName': 'Fake', 'LastName': 'Fake'}, 'Banned', function(Err, Result) {
                                            Store.Get({'FirstName': 'Fake', 'LastName': 'Fake', 'Email': 'FakeToo'}, function(Err, Result) {
                                                var HasSuspended = Result.Memberships.some(function(Item, Index, List) {
                                                    return Item == 'Suspended';
                                                });
                                                var HasBanned = Result.Memberships.some(function(Item, Index, List) {
                                                    return Item == 'Banned';
                                                });
                                                Test.ok(Result['Memberships'].length==2&&HasSuspended&&HasBanned, "Confirming that adding more memberships works.");
                                                Callback();
                                            });
                                        });
                                    });
                                });
                            });
                        });
                    });
                },
                function(Callback) {
                    Store.RemoveMembership({'FirstName': 'Fake', 'LastName': 'Fake'}, 'Suspended', function(Err, Result) {
                        Store.Get({'FirstName': 'Fake', 'LastName': 'Fake', 'Email': 'FakeToo'}, function(Err, Result) {
                            var HasSuspended = Result.Memberships.some(function(Item, Index, List) {
                                return Item == 'Suspended';
                            });
                            var HasBanned = Result.Memberships.some(function(Item, Index, List) {
                                return Item == 'Banned';
                            });
                            Test.ok(Result['Memberships'].length==1&&(!HasSuspended)&&HasBanned, "Confirming that deleting a membership works.");
                            Store.RemoveMembership({'FirstName': 'Fake', 'LastName': 'Fake'}, 'Banned', function(Err, Result) {
                                Store.Get({'FirstName': 'Fake', 'LastName': 'Fake', 'Email': 'FakeToo'}, function(Err, Result) {
                                    Test.ok(Result['Memberships'].length==0, "Confirming that deleting a membership works.");
                                    Callback();
                                });
                            });
                        });
                    });
                }], 
                function(Err) {
                    Test.done();
                });
            });
        });
    },
    'TestRestrictions': function(Test) {
        Test.expect(10);
        var StoreOptions = {'Indices': [{'Fields': {'FirstName': 1, 'LastName': 1}, 'Options': {'unique': true}}]};
        UserStore(Context['DB'], {'Email': {'Unique': 1, 'NotNull': 1}, 'FirstName': {'NotNull': 1}, 'Username': {'Unique': 1}}, function(Err, Store) {
            Context['DB'].collection('Users', function(Err, UsersCollection) {
                Nimble.series([
                function(Callback) {
                    Store.Add({}, function(Err, Result) { 
                        Test.ok(Err && Err.UserStore && Err.UserStore.Type == 'NotNull', "Confirming null constraint works, case 1.");
                        Store.Add({'FirstName': 'Fake'}, function(Err, Result) {
                            Test.ok(Err && Err.UserStore && Err.UserStore.Type == 'NotNull', "Confirming null constraint works, case 2.");
                            Store.Add({'Email': 'Fake@email.com'}, function(Err, Result) {
                                Test.ok(Err && Err.UserStore && Err.UserStore.Type == 'NotNull', "Confirming null constraint works, case 3.");
                                Store.Add({'FirstName': 'Fake', 'Email': 'Fake@email.com'}, function(Err, Result) {
                                    Test.ok((!Err)&&Result&&(Result.length==1), "Confirming null constraint works, case 4.");
                                    Callback();
                                });
                            });
                        });
                    });
                },
                function(Callback) {
                    Store.Add({'FirstName': 'Fake2', 'Email': 'Fake@email.com'}, function(Err, Result) {
                        Test.ok(Err && Err.UserStore && Err.UserStore.Type == 'Unique', "Confirming unique constraint works, case 1.");
                        Store.Add({'FirstName': 'Fake', 'Email': 'Fake2@email.com'}, function(Err, Result) {
                            Test.ok(Err && Err.UserStore && Err.UserStore.Type == 'Unique', "Confirming unique constraint works, case 2.");
                            Store.Add({'FirstName': 'Fake', 'Email': 'Fake2@email.com', 'LastName': null}, function(Err, Result) {
                                Test.ok(Err && Err.UserStore && Err.UserStore.Type == 'Unique', "Confirming unique constraint works, case 3.");
                                Store.Add({'FirstName': 'Fake', 'Email': 'Fake2@email.com', 'LastName': 'Fake'}, function(Err, Result) {
                                    Test.ok((!Err)&&Result&&(Result.length==1), "Confirming null constraint works, case 4.");
                                    Store.Add({'FirstName': 'Fake2', 'Email': 'Fake3@email.com', 'LastName': 'Fake2', 'Username': 'Fake'}, function(Err, Result) {
                                        Test.ok((!Err)&&Result&&(Result.length==1), "Confirming null constraint works, case 5.");
                                        Store.Add({'FirstName': 'Fake3', 'Email': 'Fake4@email.com', 'LastName': 'Fake3', 'Username': 'Fake'}, function(Err, Result) {
                                            Test.ok(Err && Err.UserStore && Err.UserStore.Type == 'Unique', "Confirming unique constraint works, case 6.");
                                            Callback();
                                        });
                                    });
                                });
                            });
                        });
                    });
                }], 
                function(Err) {
                    Test.done();
                });
            });
        }, StoreOptions);
    },
    'TestPasswords': function(Test) {
        Test.expect(8);
        var StoreOptions = {'Indices': [{'Fields': {'FirstName': 1, 'LastName': 1}, 'Options': {'unique': true}}]};
        UserStore(Context['DB'], {'Email': {'Unique': 1, 'NotNull': 1}, 'FirstName': {'NotNull': 1}, 'Username': {'Unique': 1}}, function(Err, Store) {
            TestPassword(Test, Store);
        }, StoreOptions);
    },
    'TestCustomHash': function(Test) {
        Test.expect(8);
        var StoreOptions = {'Indices': [{'Fields': {'FirstName': 1, 'LastName': 1}, 'Options': {'unique': true}}], 'Hash': BcryptHash, 'Verify': BcryptVerify};
        UserStore(Context['DB'], {'Email': {'Unique': 1, 'NotNull': 1}, 'FirstName': {'NotNull': 1}, 'Username': {'Unique': 1}}, function(Err, Store) {
            TestPassword(Test, Store);
        }, StoreOptions);
    }
};

exports.Error = {
};

process.on('uncaughtException', function(MainErr) {
    if(Context.DB)
    {
        Context.DB.dropDatabase(function(Err, Result) {
            if(Err)
            {
                console.log(Err);
            }
            console.log('Caught exception: ' + MainErr);
            process.exit(1);
        });
    }
    else
    {
        console.log('Caught exception: ' + MainErr);
        process.exit(1);
    }
});
