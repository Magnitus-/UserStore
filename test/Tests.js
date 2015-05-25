//Copyright (c) 2015 Eric Vallee <eric_vallee2003@yahoo.ca>
//MIT License: https://raw.githubusercontent.com/Magnitus-/UserStore/master/License.txt

global.Promise = require('bluebird');
var MongoDB = require('mongodb');
var UserStore = require('../lib/UserStore');
var Bcrypt = require('bcrypt');
var Nimble = require('nimble');
var UserProperties = require('user-properties');

var Context = {};
var RandomIdentifier = 'UserStoreTestDB'+Math.random().toString(36).slice(-8);

function In()
{
    var InList = arguments[0];
    var CheckList = Array.prototype.slice.call(arguments, 1);
    return(CheckList.every(function(CheckItem) {
        return(InList.some(function(RefItem) {
            return RefItem===CheckItem;
        }));
    }));
}

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
            Context['DB'].listCollections({'name': Context['CollectionName']}).toArray(function(Err, Collections) {
                Test.ok(Collections.length==0, "Confirming that no dependencies are created if dependencies as flagged as ok.");
                Context['DependenciesOk'] = false;
                UserStore.prototype.UnitTests.EnsureDependencies.call(Context, null, function(Err) {
                    Context['DB'].listCollections({'name': Context['CollectionName']}).toArray(function(Err, Collections) {
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
            Test.ok((!Err)&&Result===null, "Confirming that empty password is no match for get");
            Store.Get({'FirstName': 'NonExistent', 'LastName': 'NonExistent', 'Email': 'NonExistent', 'Password': 'NonExistent'}, function(Err, Result) {
                Test.ok((!Err)&&Result===null, "Confirming that non-existent users are still handled properly with passwords");
                Store.Remove({'FirstName': 'Fake', 'LastName': 'FakeToo', 'Password': 'Wrong'}, function(Err, Result) {
                    Test.ok(Result===0, "Confirming that removes are not executed with the wrong password");
                    Store.Update({'FirstName': 'Fake', 'LastName': 'FakeToo', 'Password': 'WrongToo'}, {'SomeField': 'Hello world!'}, function(Err, Result) {
                        Test.ok(Result===0, "Confirming that updates are not executed with the wrong password");
                        Store.Get({'FirstName': 'Fake', 'LastName': 'FakeToo', 'Password': 'FakeAgain'}, function(Err, Result) {
                            Test.ok(Result, "Confirming that Get with the right password works.");
                            Store.Update({'FirstName': 'Fake', 'LastName': 'FakeToo', 'Password': 'FakeAgain'}, {'Password': 'FakeAgain2'}, function(Err, Result) {
                                Test.ok(Result===1, "Confirming that updates are executed with the right password");
                                Store.Get({'FirstName': 'Fake', 'LastName': 'FakeToo', 'Password': 'FakeAgain2'}, function(Err, Result) {
                                    Test.ok(Result, "Confirming that updating password works.");
                                    Store.AddMembership({'FirstName': 'Fake', 'LastName': 'FakeToo', 'Password': 'Wrong'}, 'Banned', function(Err, Result) {
                                        Test.ok(Result===0, "Confirming that memberships are not added with wrong password");
                                        Store.AddMembership({'FirstName': 'Fake', 'LastName': 'FakeToo', 'Password': 'FakeAgain2'}, 'Banned', function(Err, Result) {
                                            Test.ok(Result===1, "Confirming that memberships are added with right password");
                                            Store.RemoveMembership({'FirstName': 'Fake', 'LastName': 'FakeToo', 'Password': 'Wrong'}, 'Banned', function(Err, Result) {
                                                Test.ok(Result===0, "Confirming that memberships are not removed with wrong password");
                                                Store.RemoveMembership({'FirstName': 'Fake', 'LastName': 'FakeToo', 'Password': 'FakeAgain2'}, 'Banned', function(Err, Result) {
                                                    Test.ok(Result===1, "Confirming that memberships are removed with right password");
                                                    Store.Remove({'FirstName': 'Fake', 'LastName': 'FakeToo', 'Password': 'FakeAgain2'}, function(Err, Result) {
                                                        Test.ok(Result===1, "Confirming that removing with the right password works.");
                                                        Test.done();
                                                    });
                                                });
                                            });
                                        });
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

function TestMultipleHash(Test, Store)
{
    Store.Add({'FirstName': 'Fake', 'LastName': 'FakeToo', 'Email': 'Fake@email.com', 'Password': 'FakeAgain', 'EmailToken': 'Token!'}, function(Err, Result) {
        Store.Get({'FirstName': 'Fake', 'LastName': 'FakeToo', 'Password': 'Wrong', 'EmailToken': 'Wrong'}, function(Err, Result) {
            Test.ok((!Err)&&Result===null, "Confirming that Get doesn't match if all hashed fields are wrong.");
            Store.Get({'FirstName': 'Fake', 'LastName': 'FakeToo', 'Password': 'FakeAgain', 'EmailToken': 'Wrong'}, function(Err, Result) {
                Test.ok((!Err)&&Result===null, "Confirming that Get doesn't match if some hashed fields are wrong.");
                Store.Get({'FirstName': 'Fake', 'LastName': 'FakeToo', 'Email': 'Fake@email.com', 'Password': 'FakeAgain', 'EmailToken': 'Token!'}, function(Err, Result) {
                    Test.ok(Result, "Confirming that Get with all the right hashed fields work.");
                    Store.Update({'FirstName': 'Fake', 'LastName': 'FakeToo', 'Email': 'Fake@email.com', 'Password': 'Wrong', 'EmailToken': 'Wrong'}, {'FirstName': 'Ni!'}, function(Err, Result) {
                        Test.ok(Result===0, "Confirming that Update doesn't match if all hashed fields are wrong");    
                        Store.Update({'FirstName': 'Fake', 'LastName': 'FakeToo', 'Email': 'Fake@email.com', 'Password': 'Wrong', 'EmailToken': 'Token!'}, {'FirstName': 'Ni!'}, function(Err, Result) {
                            Test.ok(Result===0, "Confirming that Update doesn't match if some hashed fields are wrong"); 
                            Store.Update({'FirstName': 'Fake', 'LastName': 'FakeToo', 'Email': 'Fake@email.com', 'Password': 'FakeAgain', 'EmailToken': 'Token!'}, {'FirstName': 'Ni!'}, function(Err, Result) {
                                Test.ok(Result===1, "Confirming that Update matches if all hashed fields are right");
                                Store.Remove({'FirstName': 'Ni!', 'LastName': 'FakeToo', 'Password': 'Wrong', 'EmailToken': 'Wrong'}, function(Err, Result) {
                                    Test.ok(Result===0, "Confirming that Remove doesn't match if all hashed fields are wrong");
                                    Store.Remove({'FirstName': 'Ni!', 'LastName': 'FakeToo', 'Password': 'FakeAgain', 'EmailToken': 'Wrong'}, function(Err, Result) {
                                        Test.ok(Result===0, "Confirming that Remove doesn't match if some hashed fields are wrong");
                                        Store.Update({'FirstName': 'Ni!', 'LastName': 'FakeToo', 'Email': 'Fake@email.com', 'Password': 'FakeAgain', 'EmailToken': 'Token!'}, {'Password': 'FakeAgain2', 'EmailToken': 'Token!2'}, function(Err, Result) {
                                            Store.Remove({'FirstName': 'Ni!', 'LastName': 'FakeToo', 'Email': 'Fake@email.com', 'Password': 'FakeAgain2', 'EmailToken': 'Token!2'}, function(Err, Result) {
                                                Test.ok(Result===1, "Confirming that Remove matches if all hashed fields are right and that updating hashed fields work.");
                                                Test.done();
                                            });
                                        });
                                    });
                                });
                            });
                        });
                    });
                })
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
        Test.expect(29);
        UserStore(Context['DB'], UserProperties(), function(Err, Store) {
            Context['DB'].collection('Users', function(Err, UsersCollection) {
                Nimble.series([
                function(Callback) {
                    Store.Count({'FirstName': 'Fake'}, function(Err, Count) {
                        Test.ok(Count===0, "Confirming that count returns 0 when no users match the criteria.");
                        Callback();
                    });
                },
                function(Callback) {
                    Store.Add({'FirstName': 'Fake', 'LastName': 'Name'}, function(Err, Result) {
                        Test.ok(Result.length===1, "Confirming that insertion of first element works.");
                        Callback();
                    });
                },
                function(Callback) {
                    Store.Count({'FirstName': 'Fake'}, function(Err, Count) {
                        Test.ok(Count===1, "Confirming that count works when a user is matched.");
                        Callback();
                    });
                },
                function(Callback) {
                    Store.Get({'FirstName': 'Fake', 'LastName': 'Name'}, function(Err, Result) {
                        Test.ok(Result['FirstName']==='Fake' && Result['LastName']==='Name', "Confirming that get on first element works.");
                        Callback();
                    });
                },
                function(Callback) {
                    Store.Add({'FirstName': 'Fake2', 'LastName': 'Name2'}, function(Err, Result) {
                        Test.ok(Result.length===1, "Confirming that insertion of subsequent elements works.");
                        Callback();
                    });

                },
                function(Callback) {
                    Store.Get({'FirstName': 'Fake2'}, function(Err, Result) {
                        Test.ok(Result['FirstName']==='Fake2' && Result['LastName']==='Name2', "Confirming that get on subsequent elements works.");
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
                                Test.ok(RemovedAmount===0&&Result1&&Result2, "Confirming that removing non-existent users doesn't remove any.");
                                Callback();
                            });
                        });
                    });
                },
                function(Callback) {
                    Store.Remove({'FirstName': 'Fake'}, function(Err, RemovedAmount) {
                        Store.Get({'FirstName': 'Fake', 'LastName': 'Name'}, function(Err, Result) {
                            Test.ok(RemovedAmount===1&&Result===null, "Confirming that removing an element works.");
                            Callback();
                        });
                    });
                },
                function(Callback) {
                    Store.Remove({'FirstName': 'Fake2'}, function(Err, RemovedAmount) {
                        Store.Get({'FirstName': 'Fake2', 'LastName': 'Name2'}, function(Err, Result) {
                            Test.ok(RemovedAmount===1&&Result===null, "Confirming that removing last element works.");
                            Callback();
                        });
                    });
                },
                function(Callback) {
                    Store.Add({'FirstName': 'Fake', 'LastName': 'Name'}, function(Err, Result) {
                        Store.Update({'FirstName': 'Fake'}, {'LastName': 'Fake', 'Email': 'FakeToo'}, function(Err, Result) {
                            Test.ok(Result===1, "Confirming that update took place.");
                            Store.Get({'FirstName': 'Fake', 'LastName': 'Fake', 'Email': 'FakeToo'}, function(Err, Result) {
                                Test.ok(Result, "Confirming that the right fields got updated.");
                                Callback();
                            });
                        });
                    });
                },
                function(Callback) {
                    Store.Get({'FirstName': 'Fake', 'LastName': 'Fake', 'Email': 'FakeToo'}, function(Err, Result) {
                        Test.ok(Result['Memberships'] && Result['Memberships'].length===0, "Confirming that membership array is created by default");
                        Store.AddMembership({'FirstName': 'Fake', 'LastName': 'Fake'}, 'Suspended', function(Err, Result) {
                            Test.ok(Result===1, "Confirming that update took place.");
                            Store.Get({'FirstName': 'Fake', 'LastName': 'Fake', 'Email': 'FakeToo'}, function(Err, Result) {
                                Test.ok(Result['Memberships'][0]==='Suspended', "Confirming that the right fields got updated.");
                                Store.AddMembership({'FirstName': 'Fake', 'LastName': 'Fake'}, 'Suspended', function(Err, Result) {
                                    Store.Get({'FirstName': 'Fake', 'LastName': 'Fake', 'Email': 'FakeToo'}, function(Err, Result) {
                                        Test.ok(Result['Memberships'].length===1 && Result['Memberships'][0]==='Suspended', "Confirming that membership array works as a set.");
                                        Store.AddMembership({'FirstName': 'Fake', 'LastName': 'Fake'}, 'Banned', function(Err, Result) {
                                            Store.Get({'FirstName': 'Fake', 'LastName': 'Fake', 'Email': 'FakeToo'}, function(Err, Result) {
                                                var HasSuspended = Result.Memberships.some(function(Item, Index, List) {
                                                    return Item == 'Suspended';
                                                });
                                                var HasBanned = Result.Memberships.some(function(Item, Index, List) {
                                                    return Item == 'Banned';
                                                });
                                                Test.ok(Result['Memberships'].length===2&&HasSuspended&&HasBanned, "Confirming that adding more memberships works.");
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
                },
                function(Callback) {
                    Store.Add({'FirstName': 'FakeSibling', 'LastName': 'Fake'}, function(Err, Result) {
                        Store.Count({'LastName': 'Fake'}, function(Err, Count) {
                            Test.ok(Count==2, "Confirming that count against criteria that match more than 1 user works.");
                            Callback();
                        });
                    });
                },
                function(Callback) {
                    Store.Add({'FirstName': 'Anatoly', 'LastName': 'Baranoly', 'Email': 'Anatoly@fakemail.com', 'Username': 'Original'}, function(Err, Result) {
                        Store.UpdateAtomic({'Email': 'Anatoly@fakemail.com'}, {'FirstName': 'Anatolium'}, null, function(Err, Result) {
                            Store.Get({'Email': 'Anatoly@fakemail.com'}, function(Err, User) {
                                Test.ok(User.FirstName==='Anatolium' && User.Memberships.length === 0, "Confirming UpdateAtomic without membership changes works.");
                                Store.UpdateAtomic({'Email': 'Anatoly@fakemail.com'}, {'LastName': 'Baranolium'}, {'Add': 'Test1'}, function(Err, Result) {
                                    Store.Get({'Email': 'Anatoly@fakemail.com'}, function(Err, User) {
                                        Test.ok(User.LastName==='Baranolium' && User.Memberships.length === 1 && In(User.Memberships, 'Test1'), "Confirming UpdateAtomic works with adding a single group.");
                                        Store.UpdateAtomic({'Email': 'Anatoly@fakemail.com'}, {'FirstName': 'Anatola', 'LastName': 'Baranola'}, {'Add': ['Test1', 'Test2', 'Test3']}, function(Err, Result) {
                                            Store.Get({'Email': 'Anatoly@fakemail.com'}, function(Err, User) {
                                                Test.ok(User.LastName==='Baranola' && User.FirstName==='Anatola' && User.Memberships.length === 3 && In(User.Memberships, 'Test1', 'Test2', 'Test3'), "Confirming UpdateAtomic can add multiple groups and preserves set uniqueness.");
                                                Store.UpdateAtomic({'Email': 'Anatoly@fakemail.com'}, {'FirstName': 'Anatolu', 'LastName': 'Baranolu'}, {'Remove': 'Test3'}, function(Err, Result) {
                                                    Store.Get({'Email': 'Anatoly@fakemail.com'}, function(Err, User) {
                                                        Test.ok(User.LastName==='Baranolu' && User.FirstName==='Anatolu' && User.Memberships.length === 2 && In(User.Memberships, 'Test1', 'Test2'), "Confirming UpdateAtomic can remove a single group.");
                                                        Store.UpdateAtomic({'Email': 'Anatoly@fakemail.com'}, {'FirstName': 'Anatolo', 'LastName': 'Baranolo'}, {'Remove': ['Test1', 'Test2', 'Test3']}, function(Err, Result) {
                                                            Store.Get({'Email': 'Anatoly@fakemail.com'}, function(Err, User) {
                                                                Test.ok(User.LastName==='Baranolo' && User.FirstName==='Anatolo' && User.Memberships.length === 0, "Confirming UpdateAtomic can remove multiple groups.");
                                                                Callback();
                                                            });
                                                        });
                                                    });
                                                });
                                            });
                                        });
                                    });
                                });
                            });
                        });
                    });
                },
                function(Callback) {
                    Store.Add({'FirstName': 'Boromir', 'LastName': 'Boromir', 'Email': 'Boromir@fakemail.com', 'Username': 'Boromir'}, function(Err, Result) {
                        Store.UpdateGet({'FirstName': 'Boromir'}, {'LastName': 'Boromiron'}, function(Err, User) {
                            Test.ok(User.LastName==='Boromiron' && User.FirstName==='Boromir' && User.Memberships.length === 0, "Confirming UpdateGet updates and retrieves updated user.");
                            Store.UpdateGet({'FirstName': 'Borom'}, {'LastName': 'Boromiron'}, function(Err, User) {
                                Test.ok(User === null, "Confirming that calling UpdateGet for a non-existent user returns null.");
                                Store.UpdateGetAtomic({'FirstName': 'Boromir'}, {'LastName': 'Boromirir'}, {'Add': 'Sup'}, function(Err, User) {
                                    Test.ok(User.LastName && User.LastName === "Boromirir" && User.Memberships && User.Memberships.length === 1 && In(User.Memberships, 'Sup'), "Confirming that UpdateGetAtomic updates and retrieves updated user.");
                                    Store.UpdateGetAtomic({'FirstName': 'Borin'}, {'LastName': 'Boromirir'}, {'Add': 'Sup'}, function(Err, User) {
                                        Test.ok(User === null, "Confirming that calling UpdateGetAtomic for a non-existent user returns null.");
                                        Callback();
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
        });
    },
    'TestRestrictions': function(Test) {
        Test.expect(16);
        var StoreOptions = {'Indices': [{'Fields': {'FirstName': 1, 'LastName': 1}, 'Options': {'unique': true}}]};
        var UserSchema = UserProperties({'Email': {'Required': true, 'Unique': true},
                                         'FirstName': {'Required': true},
                                         'Username': {'Unique': true}});
        UserStore(Context['DB'], UserSchema, function(Err, Store) {
            Context['DB'].collection('Users', function(Err, UsersCollection) {
                Nimble.series([
                function(Callback) {
                    Store.Add({}, function(Err, Result) { 
                        Test.ok(Err && Err.UserStore && Err.UserStore.Type == 'NotNull', "Confirming null constraint works with Add, case 1.");
                        Store.Add({'FirstName': 'Fake'}, function(Err, Result) {
                            Test.ok(Err && Err.UserStore && Err.UserStore.Type == 'NotNull', "Confirming null constraint works with Add, case 2.");
                            Store.Add({'Email': 'Fake@email.com'}, function(Err, Result) {
                                Test.ok(Err && Err.UserStore && Err.UserStore.Type == 'NotNull', "Confirming null constraint works with Add, case 3.");
                                Store.Add({'FirstName': 'Fake', 'Email': 'Fake@email.com'}, function(Err, Result) {
                                    Test.ok((!Err)&&Result&&(Result.length==1), "Confirming null constraint works with Add, case 4.");
                                    Callback();
                                });
                            });
                        });
                    });
                },
                function(Callback) {
                    Store.Add({'FirstName': 'Fake2', 'Email': 'Fake@email.com'}, function(Err, Result) {
                        Test.ok(Err && Err.UserStore && Err.UserStore.Type == 'Unique', "Confirming unique constraint works with Add, case 1.");
                        Store.Add({'FirstName': 'Fake', 'Email': 'Fake2@email.com'}, function(Err, Result) {
                            Test.ok(Err && Err.UserStore && Err.UserStore.Type == 'Unique', "Confirming unique constraint works with Add, case 2.");
                            Store.Add({'FirstName': 'Fake', 'Email': 'Fake2@email.com', 'LastName': null}, function(Err, Result) {
                                Test.ok(Err && Err.UserStore && Err.UserStore.Type == 'Unique', "Confirming unique constraint works with Add, case 3.");
                                Store.Add({'FirstName': 'Fake', 'Email': 'Fake2@email.com', 'LastName': 'Fake'}, function(Err, Result) {
                                    Test.ok((!Err)&&Result&&(Result.length==1), "Confirming null constraint works with Add, case 4.");
                                    Store.Add({'FirstName': 'Fake2', 'Email': 'Fake3@email.com', 'LastName': 'Fake2', 'Username': 'Fake'}, function(Err, Result) {
                                        Test.ok((!Err)&&Result&&(Result.length==1), "Confirming null constraint works with Add, case 5.");
                                        Store.Add({'FirstName': 'Fake3', 'Email': 'Fake4@email.com', 'LastName': 'Fake3', 'Username': 'Fake'}, function(Err, Result) {
                                            Test.ok(Err && Err.UserStore && Err.UserStore.Type == 'Unique', "Confirming unique constraint works with Add, case 6.");
                                            Callback();
                                        });
                                    });
                                });
                            });
                        });
                    });
                },
                //Profiles:
                //'FirstName': 'Fake', 'Email': 'Fake@email.com'
                //'FirstName': 'Fake', 'Email': 'Fake2@email.com', 'LastName': 'Fake'
                //'FirstName': 'Fake2', 'Email': 'Fake3@email.com', 'LastName': 'Fake2', 'Username': 'Fake'
                function(Callback) {
                    Store.Update({'Email': 'Fake@email.com'}, {'Email': null}, function(Err, Result) {
                        Test.ok(Err && Err.UserStore && Err.UserStore.Type == 'NotNull', "Confirming null constraint works with Update, case 1.");
                        Store.Update({'Email': 'Fake@email.com'}, {'Email': undefined}, function(Err, Result) {
                            Test.ok(Err && Err.UserStore && Err.UserStore.Type == 'NotNull', "Confirming null constraint works with Update, case 2.");
                            Callback();
                        });
                    });
                },
                function(Callback) {
                    Store.Update({'Email': 'Fake@email.com'}, {'Email': 'Fake2@email.com'}, function(Err, Result) {
                        Test.ok(Err && Err.UserStore && Err.UserStore.Type == 'Unique', "Confirming null constraint works with Update, case 1.");
                        Store.Update({'Email': 'Fake@email.com'}, {'Username': 'Fake'}, function(Err, Result) {
                            Test.ok(Err && Err.UserStore && Err.UserStore.Type == 'Unique', "Confirming null constraint works with Update, case 2.");
                            Store.Update({'Email': 'Fake2@email.com'}, {'FirstName': 'Fake2'}, function(Err, Result) {
                                Test.ok(!Err, "Confirming null constraint works with Update, case 3.");
                                Store.Update({'Email': 'Fake2@email.com'}, {'LastName': 'Fake2'}, function(Err, Result) {
                                    Test.ok(Err && Err.UserStore && Err.UserStore.Type == 'Unique', "Confirming null constraint works with Update, case 4.");
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
        }, StoreOptions);
    },
    'TestPasswords': function(Test) {
        Test.expect(12);
        var UserSchema = UserProperties({'Email': {'Required': true, 'Unique': true},
                                         'FirstName': {'Required': true},
                                         'Username': {'Unique': true},
                                         'Password': {'Retrievable': false, 'Privacy': UserProperties.Privacy.Secret}});
        var StoreOptions = {'Indices': [{'Fields': {'FirstName': 1, 'LastName': 1}, 'Options': {'unique': true}}]};
        UserStore(Context['DB'], UserSchema, function(Err, Store) {
            TestPassword(Test, Store);
        }, StoreOptions);
    },
    'TestCustomHash': function(Test) {
        Test.expect(12);
        var UserSchema = UserProperties({'Email': {'Required': true, 'Unique': true},
                                         'FirstName': {'Required': true},
                                         'Username': {'Unique': true},
                                         'Password': {'Retrievable': false, 'Privacy': UserProperties.Privacy.Secret}});
        var StoreOptions = {'Indices': [{'Fields': {'FirstName': 1, 'LastName': 1}, 'Options': {'unique': true}}], 'Hash': BcryptHash, 'Verify': BcryptVerify};
        UserStore(Context['DB'], UserSchema, function(Err, Store) {
            TestPassword(Test, Store);
        }, StoreOptions);
    },
    'TestMultipleHash': function(Test) {
        Test.expect(9);
        var UserSchema = UserProperties({'Email': {'Required': true, 'Unique': true},
                                         'FirstName': {'Required': true},
                                         'Username': {'Unique': true},
                                         'Password': {'Retrievable': false, 'Privacy': UserProperties.Privacy.Secret},
                                         'EmailToken': {'Retrievable': false, 'Privacy': UserProperties.Privacy.Secret}});
        var StoreOptions = {'Indices': [{'Fields': {'FirstName': 1, 'LastName': 1}, 'Options': {'unique': true}}]};
        UserStore(Context['DB'], UserSchema, function(Err, Store) {
            TestMultipleHash(Test, Store);
        }, StoreOptions);
    },
    'TestMultipleUseOneHash': function(Test) {
        Test.expect(12);
        var UserSchema = UserProperties({'Email': {'Required': true, 'Unique': true},
                                         'FirstName': {'Required': true},
                                         'Username': {'Unique': true},
                                         'Password': {'Retrievable': false, 'Privacy': UserProperties.Privacy.Secret},
                                         'EmailToken': {'Retrievable': false, 'Privacy': UserProperties.Privacy.Secret}});
        var StoreOptions = {'Indices': [{'Fields': {'FirstName': 1, 'LastName': 1}, 'Options': {'unique': true}}], 'Hash': BcryptHash, 'Verify': BcryptVerify};
        UserStore(Context['DB'], UserSchema, function(Err, Store) {
            TestPassword(Test, Store);
        }, StoreOptions);
    },
    'TestHashOnly': function(Test) {
        Test.expect(1);
        var UserSchema = UserProperties({'Email': {'Required': true, 'Unique': true},
                                         'FirstName': {'Required': true},
                                         'Username': {'Unique': true},
                                         'Password': {'Retrievable': false, 'Privacy': UserProperties.Privacy.Secret},
                                         'EmailToken': {'Retrievable': false, 'Privacy': UserProperties.Privacy.Secret}});
        var StoreOptions = {'Indices': [{'Fields': {'FirstName': 1, 'LastName': 1}, 'Options': {'unique': true}}], 'HashOnly': ['Password']};
        UserStore(Context['DB'], UserSchema, function(Err, Store) {
            Store.Add({'FirstName': 'Fake', 'LastName': 'FakeToo', 'Email': 'Fake@email.com', 'Password': 'FakeAgain', 'EmailToken': 'Token!'}, function(Err, Result) {
                Store.Get({'FirstName': 'Fake'}, function(Err, User) {
                    Test.ok(User.EmailToken === 'Token!' && 'Password' !== 'FakeAgain', "Confirming that only the password is hashed");
                    Test.done();
                });
            });
        }, StoreOptions);
    },
    'TestPromise': function(Test) {
        function Done()
        {
            Test.done();
        }
        function LogError(Err)
        {
            console.log(Err);
            return Err;
        }
        Test.expect(11);
        var StoreOptions = {'Indices': [{'Fields': {'FirstName': 1, 'LastName': 1}, 'Options': {'unique': true}}]};
        var UserSchema = UserProperties({'Email': {'Required': true, 'Unique': true},
                                         'FirstName': {'Required': true},
                                         'Username': {'Unique': true}});
        var Store = null;
        var StoreCreation = UserStore(Context['DB'], UserSchema, StoreOptions);
        
        var ValidUserCreation = StoreCreation.then(function(StoreInstance) {
            Store = StoreInstance;
            Test.ok(Store, "Confirming that constructor with valid arguments works with promise API.");
            return Store.Add({'FirstName': 'Promise', 'LastName': 'Promise', 'Email': 'Promise', 'Username': 'Promise'});
        }, LogError);
        
        var InvalidUserCreation = ValidUserCreation.then(function(Result) {
            Test.ok(Result && Result.length === 1 && Result[0].Username === 'Promise' && Result[0].Email === 'Promise', "Confirming that adding valid new user with promise API works fine.");
            return Store.Add({'FirstName': 'Promise', 'LastName': 'Promise', 'Email': 'Promise', 'Username': 'Promise'});
        }, LogError)
        
        var ValidUserUpdate = InvalidUserCreation.catch(function(Err) {
            Test.ok(Err && Err.UserStore, "Confirming that adding invalid new user with promise API works fine");
            return Store.Update({'Username': 'Promise'}, {'FirstName': 'Promised'});
        })
        
        var InvalidUserUpdate = ValidUserUpdate.then(function(Result) {
            Test.ok(Result===1, "Confirming that valid updates work with promise API.");
            return Store.Update({'Username': 'Promise'}, {'FirstName': null});
        }, LogError)
        
        
        var UserGet = InvalidUserUpdate.catch(function(Err) {
            Test.ok(Err && Err.UserStore, "Confirming that invalid updates with promise API works fine");
            return Store.Get({'Username': 'Promise'});
        });
        
        var UserRemove = UserGet.then(function(User) {
            Test.ok(User && User.Username === 'Promise' && User.FirstName === 'Promised', "Confirming that getting a user works with promise API");
            return Store.Remove({'Username': 'Promise'});
        }, LogError)
        
        var AddMembership = UserRemove.then(function(Result) {
            Test.ok(Result===1, "Confirming that deletion works with promise API.");
            return Store.Add({'FirstName': 'Promise', 'LastName': 'Promise', 'Email': 'Promise', 'Username': 'Promise'});
        }, LogError).then(function(Result) {
            return Store.AddMembership({'FirstName': 'Promise'}, 'Test');
        }, LogError);
        
        var RemoveMembership = AddMembership.then(function(Result) {
            Test.ok(Result===1, "Confirming that adding memberships works with promise API");
            return Store.RemoveMembership({'FirstName': 'Promise'}, 'Test');
        }, LogError);
        
        var Count = RemoveMembership.then(function(Result) {
            Test.ok(Result===1, "Confirming that removing memberships works with promise API");
            return Store.Count({'FirstName': 'Promise'});
        }, LogError);
        
        var UpdateAtomic = Count.then(function(Result) {
            Test.ok(Result===1, "Confirming that count works with promise API");
            return Store.UpdateAtomic({'FirstName': 'Promise'}, {'LastName': 'Promised'}, {'Add': 'Test'});
        }, LogError);
        
        UpdateAtomic.then(function(Result) {
            Test.ok(Result===1, "Confirming that UpdateAtomic works with promise API");
            return true;
        }, LogError).then(Done, Done);
    }
};

if(process.env['USER'] && process.env['USER']==='root')
{
    
    //http://stackoverflow.com/questions/26743770/simulating-failure-to-access-mongodb/26750101#26750101
    function SleepMongoDB(DB, Callback)
    {
        DB.command({'serverStatus': 1}, function(Err, Result) {
            Context['PID'] = Result.pid;
            process.kill(Context.PID, 'SIGSTOP');
            Callback();
        });
    }
    
    function TestSleep(Test, Callback)
    {
        Test.expect(1);
        var UserSchema = UserProperties({'Email': {'Required': true, 'Unique': true},
                                         'FirstName': {'Required': true},
                                         'Username': {'Unique': true},
                                         'Password': {'Retrievable': false, 'Privacy': UserProperties.Privacy.Secret}});
        var StoreOptions = {'Indices': [{'Fields': {'FirstName': 1, 'LastName': 1}, 'Options': {'unique': true}}], 'HashOnly': ['Password']};
        UserStore(Context['DB'], UserSchema, function(Err, Store) {
            Store.Add({'Email': 'ma@ma.ma', 'FirstName': 'Fake', 'LastName': 'Fake', 'Username': 'Fake', 'Password': 'Qwerty!'}, function(Err, Result) {
                SleepMongoDB(Context['DB'], function() {
                    Callback(Store);
                });
            });
        });
    }
    
    exports.NonResponsiveHandling = {
        'setUp': function(Callback) {
            MongoDB.MongoClient.connect("mongodb://localhost:27017/"+RandomIdentifier, {'db': {native_parser: true}, 'server': {'socketOptions': {'connectTimeoutMS': 50, 'socketTimeoutMS': 50}}}, function(Err, DB) {
                Context['DB'] = DB;
                Callback();
            });
        },
        'tearDown': function(Callback) {
            if(Context.PID)
            {
                process.kill(Context.PID, 'SIGCONT');
                Context.DB.close();
                //Setting socketTimeoutMS > 0 is not recommended in production without addtional re-connection logic as it will close the connection when it times out and will also trigger closure if it is iddle (ie, not making any requests) for the given duration
                //It works well for these tests as there isn't much of a delay between requests or a need to make additional requests with the same DB handle after failure
                MongoDB.MongoClient.connect("mongodb://localhost:27017/"+RandomIdentifier, {'server': {'socketOptions': {'connectTimeoutMS': 50, 'socketTimeoutMS': 50}}}, function(Err, DB) {
                    DB.dropDatabase(function(Err, Result) {
                        if(Err)
                        {
                            console.log(Err);
                        }
                        DB.close();
                        Context['DB'] = null;
                        Context['PID'] = null
                        Callback();
                    });
                });
            }
            else
            {
                Context.DB.dropDatabase(function(Err, Result) {
                    if(Err)
                    {
                        console.log(Err);
                    }
                    Context.DB.close();
                    Context['DB'] = null;
                    Context['PID'] = null
                    Callback();
                });
            }
        },
        'Constructor': function(Test) {
            Test.expect(1);
            var UserSchema = UserProperties({'Email': {'Required': true, 'Unique': true},
                                             'FirstName': {'Required': true},
                                             'Username': {'Unique': true},
                                             'Password': {'Retrievable': false, 'Privacy': UserProperties.Privacy.Secret}});
            var StoreOptions = {'Indices': [{'Fields': {'FirstName': 1, 'LastName': 1}, 'Options': {'unique': true}}], 'HashOnly': ['Password']};
            SleepMongoDB(Context['DB'], function() {
                UserStore(Context['DB'], UserSchema, function(Err, Store) {
                    Test.ok(Err, "Confirming that constructor handles socket timeout properly");
                    Test.done();
                });
            });
        },
        'Add': function(Test) {
            Test.expect(1);
            var UserSchema = UserProperties({'Email': {'Required': true, 'Unique': true},
                                             'FirstName': {'Required': true},
                                             'Username': {'Unique': true},
                                             'Password': {'Retrievable': false, 'Privacy': UserProperties.Privacy.Secret}});
            var StoreOptions = {'Indices': [{'Fields': {'FirstName': 1, 'LastName': 1}, 'Options': {'unique': true}}], 'HashOnly': ['Password']};
            UserStore(Context['DB'], UserSchema, function(Err, Store) {
                SleepMongoDB(Context['DB'], function() {
                    Store.Add({'Email': 'ma@ma.ma', 'FirstName': 'Fake', 'LastName': 'Fake', 'Username': 'Fake', 'Password': 'Qwerty!'}, function(Err, Result) {
                        Test.ok(Err, "Confirming that Add method handles socket timeout properly");
                        Test.done();
                    });
                });
            });
        },
        'Remove': function(Test) {
            TestSleep(Test, function(Store) {
                Store.Remove({'Email': 'ma@ma.ma'}, function(Err, Result) {
                    Test.ok(Err, "Confirming that Remove method handles socket timeout properly");
                    Test.done();
                });
            });
        },
        'Update': function(Test) {
            TestSleep(Test, function(Store) {
                Store.Update({'Email': 'ma@ma.ma'}, {'Username': 'Fake2'}, function(Err, Result) {
                    Test.ok(Err, "Confirming that Update method handles socket timeout properly");
                    Test.done();
                });
            });
        },
        'Get': function(Test) {
            TestSleep(Test, function(Store) {
                Store.Get({'Email': 'ma@ma.ma'}, function(Err, Result) {
                    Test.ok(Err, "Confirming that Get method handles socket timeout properly");
                    Test.done();
                });
            });
        },
        'AddMembership': function(Test) {
            TestSleep(Test, function(Store) {
                Store.AddMembership({'Email': 'ma@ma.ma'}, 'Ah!', function(Err, Result) {
                    Test.ok(Err, "Confirming that AddMembership method handles socket timeout properly");
                    Test.done();
                });
            });
        },
        'RemoveMembership': function(Test) {
            TestSleep(Test, function(Store) {
                Store.RemoveMembership({'Email': 'ma@ma.ma'}, 'Ah!', function(Err, Result) {
                    Test.ok(Err, "Confirming that AddMembership method handles socket timeout properly");
                    Test.done();
                });
            });
        },
        'Count': function(Test) {
            TestSleep(Test, function(Store) {
                Store.Count({'Email': 'ma@ma.ma'}, function(Err, Result) {
                    Test.ok(Err, "Confirming that Count method handles socket timeout properly");
                    Test.done();
                });
            });
        }
    };
    
    /*MongoDB.MongoClient.connect("mongodb://localhost:27017/"+RandomIdentifier, {'server': {'socketOptions': {'connectTimeoutMS': 50, 'socketTimeoutMS': 50}}}, function(Err, DB) {
        DB.command({'buildInfo': 1}, function(Err, Result) {
            var VersionArray = Result.versionArray;
            DB.dropDatabase(function(Err, Result) {
                DB.close();
                if(VersionArray[0]>2 || (VersionArray[0]===2 && VersionArray[1]>=6))
                {
                    
                }
            });
        });
    });*/
}

process.on('uncaughtException', function(MainErr) {
    console.log('eh');
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
