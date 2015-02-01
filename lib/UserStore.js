//Copyright (c) 2015 Eric Vallee <eric_vallee2003@yahoo.ca>
//MIT License: https://raw.githubusercontent.com/Magnitus-/UserStore/master/License.txt

var Crypto = require('crypto');
var MongoDB = require('mongodb');
var Nimble = require('nimble');

function HandleError(Err, ErrCallback, OkCallback) 
{
    if(Err)
    {
        if(ErrCallback)
        {
            ErrCallback(Err);
        }
    }
    else
    {
        OkCallback();
    }
};

function CreateIndices(Collection, Indices, Callback)
{
    if(Indices && Indices.length>0)
    {
        Indices[0]['Options']['w'] = 1;
        Collection.ensureIndex(Indices[0]['Fields'], Indices[0]['Options'], function(Err, Index) {
            HandleError(Err, Callback, function() { 
               CreateIndices(Collection, Indices.slice(1), Callback);
            });
        });
    }
    else
    {
        Callback();
    }
}

function EnsureDependencies(Indices, Callback)
{
    var Self = this;
    if(!this.DependenciesOk)
    {
        Self.DB.createCollection(Self.CollectionName, {'w': 1}, function(Err, UsersCollection) {
            HandleError(Err, Callback, function() { 
                CreateIndices.call(Self, UsersCollection, Indices, function() {
                    Self.DependenciesOk = true;
                    if(Callback)
                    {
                        Callback();
                    }
                });
            });
        });
    }
    else
    {
        Callback();
    }
}

function EnforceNotNull(User)
{
    var Self = this;
    return(this.NotNull.every(function(Item, Index, List) {
        return((Item in User)&&(User[Item]!==null)&&(User[Item]!==undefined));
    }));
}

function GenerateHashFunction(KeyLength, Iterations)
{
    return(function(Password, Callback) {
        Crypto.randomBytes(32, function(Err, Buf) {
            HandleError(Err, Callback, function() {
                var Salt = Buf.toString('base64').substring(0,35);
                Crypto.pbkdf2(Password, Salt, Iterations, KeyLength, function(Err, Hash) {
                    Callback(Err, Salt+Hash);
                });
            });
        });
    });
}

function GenerateVerifyFunction(KeyLength, Iterations)
{
    return(function(Password, Hash, Callback) {
        var Salt = Hash.substring(0,35);
        Crypto.pbkdf2(Password, Salt, Iterations, KeyLength, function(Err, PasswordHash) {
            Callback(Err, (Salt+PasswordHash)==Hash);
        });
    });
}

function SurfaceCopy(ToCopy)
{
    var Result = {};
    for(Key in ToCopy)
    {
        Result[Key] = ToCopy[Key];
    }
    return Result;
}

function HashPassword(User, Callback)
{
    var UserCopy = SurfaceCopy(User);
    if(User['Password']!==null&&User['Password']!==undefined)
    {
        this.Hash(UserCopy['Password'], function(Err, Hash) {
            HandleError(Err, Callback, function() {
                UserCopy['Password']=Hash;
                Callback(null, UserCopy);
            });
        });
    }
    else
    {
        Callback(null, UserCopy);
    }
}

function GetUser(User, Callback)
{
    this.DB.collection(this.CollectionName, function(Err, UsersCollection) {
        HandleError(Err, Callback, function() { 
            UsersCollection.findOne(User, function(Err, Result) {
                Callback(Err, Result);
            });
        });
    });
}

function VerifyPassword(User, Callback)
{
    var Self = this;
    if(User['Password']!==null&&User['Password']!==undefined)
    {
        var Password = User['Password'];
        var UserCopy = SurfaceCopy(User);
        delete UserCopy['Password'];
        GetUser.call(Self, UserCopy, function(Err, UserInfo) {
            HandleError(Err, Callback, function() {
                if(UserInfo)
                {
                    Self.Verify(Password, UserInfo['Password'], function(Err, Same) {
                        Callback(Err, Same, UserInfo);
                    });
                }
                else
                {
                    Callback(null, false, null);
                }
            });
        });
    }
    else
    {
        Callback(null, true, null);
    }
}

function UserStore(DB, Restrictions, Callback, Options)
{
    if(this instanceof UserStore)
    {
        this.DB = DB;
        this.KeyLength = Options && Options.KeyLength ? Options.KeyLength : 20;
        this.Iterations = Options && Options.Iterations ? Options.Iterations : 10000;
        this.Hash = Options && Options.Hash ? Options.Hash : GenerateHashFunction(this.KeyLength, this.Iterations);
        this.Verify = Options && Options.Verify ? Options.Verify : GenerateVerifyFunction(this.KeyLength, this.Iterations);
        this.CollectionName = Options && Options.CollectionName ? Options.CollectionName : 'Users';
        this.MembershipsArray = Options && Options.MembershipsArray ? Options.MembershipsArray : true;
        
        var Indices = Options && Options.Indices ? Options.Indices : [];
        this.NotNull = [];
        if(!Indices)
        {
            Indices = [];
        }
        for(Field in Restrictions)
        {
            if(Restrictions[Field]['NotNull'])
            {
                this.NotNull.push(Field);
            }
            if(Restrictions[Field]['Unique'])
            {
                var NewIndex = {'Fields': {}, 'Options': {'unique': true}};
                NewIndex['Fields'][Field]=1;
                if(!Restrictions[Field]['NotNull'])
                {
                    NewIndex['Options']['sparse'] = true;
                }
                Indices.push(NewIndex);
            }
        }
        
        EnsureDependencies.call(this, Indices, (function(Err) {
            if(Callback)
            {
                Callback(Err, this);
            }
        }).bind(this));
    }
    else
    {
        return new UserStore(DB, Restrictions, Callback, Options);
    }
}

//Adding custom error info to isolate constraint violation errors from system errors in a backward compatible way
function AugmentError(Err, Name, Type)
{
    Err.UserStore = {};
    Err.UserStore.Name = Name;
    Err.UserStore.Type = Type;
}

function InsertUser(User, Callback)
{
    this.DB.collection(this.CollectionName, function(Err, UsersCollection) {
        HandleError(Err, Callback, function() { 
            UsersCollection.insert(User, function(Err, Result) {
                if(Err && Err.name && Err.name=='MongoError' && Err.code && Err.code == 11000)
                {
                    AugmentError(Err, 'ConstraintError', 'Unique');
                }
                Callback(Err, Result);
            });
        });
    });
}

UserStore.prototype.Add = function(User, Callback) {
    var Self = this;
    if(!EnforceNotNull.call(Self, User))
    {
        var NotNullError = new Error('UserStore: NotNull constraint not respected.');
        NotNullError.name = 'ConstraintError';
        AugmentError(NotNullError, 'ConstraintError', 'NotNull');
        Callback(NotNullError);
        return;
    }
    HashPassword.call(Self, User, function(Err, UserCopy) {
        HandleError(Err, Callback, function() {
            if(Self.MembershipsArray && (!('Memberships' in UserCopy)))
            {
                UserCopy['Memberships'] = [];
            }
            InsertUser.call(Self, UserCopy, Callback);
        });
    });
};

function RemoveUser(User, Callback)
{
    this.DB.collection(this.CollectionName, function(Err, UsersCollection) {
        HandleError(Err, Callback, function() { 
            UsersCollection.remove(User, function(Err, Result) {
                Callback(Err, Result);
            });
        });
    });
}

UserStore.prototype.Remove = function(User, Callback) {
    var Self = this;
    VerifyPassword.call(this, User, function(Err, Ok, UserInfo) {
        HandleError(Err, Callback, function() {
            if(!Ok)
            {
                Callback(null, 0);
            }
            else
            {
                if(User['Password'])
                {
                    var UserCopy = SurfaceCopy(User);
                    delete UserCopy['Password'];
                }
                else
                {
                    var UserCopy = User;
                }
                RemoveUser.call(Self, UserCopy, Callback);
            }
        });
        
    });
};

UserStore.prototype.Get = function(User, Callback) {
    var Self = this;
    VerifyPassword.call(this, User, function(Err, Ok, UserInfo) {
        HandleError(Err, Callback, function() {
            if(!Ok)
            {
                Callback(null, null);
            }
            else
            {
                if(UserInfo)
                {
                    Callback(null, UserInfo);
                }
                else //If password is not set on User
                {
                    GetUser.call(Self, User, Callback);
                }
            }
        });
    });
};

UserStore.prototype.AddMembership = function(User, Membership, Callback) {
    this.DB.collection(this.CollectionName, function(Err, UsersCollection) {
        HandleError(Err, Callback, function() { 
            UsersCollection.update(User, {'$addToSet': {'Memberships': Membership}}, function(Err, Result) {
                Callback(Err, Result);
            });
        });
    });
};

UserStore.prototype.RemoveMembership = function(User, Membership, Callback) {
    this.DB.collection(this.CollectionName, function(Err, UsersCollection) {
        HandleError(Err, Callback, function() { 
            UsersCollection.update(User, {'$pull': {'Memberships': Membership}}, function(Err, Result) {
                Callback(Err, Result);
            });
        });
    }); 
};

UserStore.prototype.Update = function(User, Updates, Callback) {
    var Self = this;
    HashPassword.call(Self, Updates, function(Err, UpdatesCopy) {
        HandleError(Err, Callback, function() {
            VerifyPassword.call(Self, User, function(Err, Ok, UserInfo) {
                HandleError(Err, Callback, function() {
                    if(Ok)
                    {
                        Self.DB.collection(Self.CollectionName, function(Err, UsersCollection) {
                            HandleError(Err, Callback, function() { 
                                var UpdateObject = {'$set': {}};
                                for(Key in UpdatesCopy)
                                {
                                    UpdateObject['$set'][Key] = UpdatesCopy[Key];
                                }
                                if(User['Password'])
                                {
                                    var UserCopy = SurfaceCopy(User);
                                    delete UserCopy['Password'];
                                }
                                else
                                {
                                    var UserCopy = User;
                                }
                                UsersCollection.update(UserCopy, UpdateObject, function(Err, Result) {
                                    Callback(Err, Result);
                                });
                            });
                        });
                    }
                    else
                    {
                        Callback(null, 0);
                    }
                });
            });
        });
    });
};

UserStore.prototype.UnitTests = {};
UserStore.prototype.UnitTests['GenerateVerifyFunction'] = GenerateVerifyFunction;
UserStore.prototype.UnitTests['GenerateHashFunction'] = GenerateHashFunction;
UserStore.prototype.UnitTests['EnsureDependencies'] = EnsureDependencies;
UserStore.prototype.UnitTests['EnforceNotNull'] = EnforceNotNull;
UserStore.prototype.UnitTests['HandleError'] = HandleError;

module.exports = UserStore;
