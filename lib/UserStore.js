//Copyright (c) 2015 Eric Vallee <eric_vallee2003@yahoo.ca>
//MIT License: https://raw.githubusercontent.com/Magnitus-/UserStore/master/License.txt

var Crypto = require('crypto');
var MongoDB = require('mongodb');
var UserProperties = require('user-properties');

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

function EnforceNotNullUpdates(Update)
{
    var Self = this;
    return(this.NotNull.every(function(Item, Index, List) {
        var NotPresent = !(Item in Update);
        var NotUndefined = Update[Item]!==undefined;
        return((NotPresent||NotUndefined)&&(Update[Item]!==null));
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

function HasHashable(User, Hashable)
{
    return(Hashable.some(function(Field) {
        return(User[Field]!==null && User[Field]!== undefined);
    }));
}

function ClearHashable(User, Hashable)
{
    Hashable.forEach(function(Field) {
        delete User[Field];
    });
}

//Recursive call to hash fields
function HashHashableRecur(User, Fields, Callback)
{
    var Self = this;
    if(Fields.length===0)
    {
        Callback(null, User);
    }
    else
    {
        var Field = Fields[0];
        Fields.shift();
        if(User[Field]!==null&&User[Field]!==undefined)
        {
            this.Hash(User[Field], function(Err, Hash) {
                HandleError(Err, Callback, function() {
                    if(Err)
                    {
                        Callback(Err);
                    }
                    else
                    {
                        User[Field]=Hash;
                        HashHashableRecur.call(Self, User, Fields, Callback);
                    }
                });
            });
        }
        else
        {
            HashHashableRecur.call(Self, User, Fields, Callback);
        }
    }
}

function HashHashable(User, Callback)
{
    var UserCopy = SurfaceCopy(User);
    HashHashableRecur.call(this, UserCopy, this.Hashable.slice(), Callback);
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

function CountUser(User, Callback)
{
    this.DB.collection(this.CollectionName, function(Err, UsersCollection) {
        HandleError(Err, Callback, function() { 
            UsersCollection.count(User, function(Err, Count) {
                Callback(Err, Count);
            });
        });
    });
}

function VerifyHashableRecur(TestValues, ReferenceUser, Callback)
{
    var Self = this;
    var Keys = Object.keys(TestValues);
    if(Keys.length===0)
    {
        Callback(null, true, ReferenceUser);
    }
    else
    {
        var Key = Keys[0];
        Self.Verify(TestValues[Key], ReferenceUser[Key], function(Err, Same) {
            HandleError(Err, Callback, function() {
                if(Same)
                {
                    delete TestValues[Key];
                    VerifyHashableRecur.call(Self, TestValues, ReferenceUser, Callback);
                }
                else
                {
                    Callback(null, false, ReferenceUser);
                }
            });
        });
    }
}

function VerifyHashable(User, Callback)
{
    var Self = this;
    var TestValues = {};
    var UserCopy = SurfaceCopy(User);
    this.Hashable.forEach(function(Field) {
        if(User[Field]!==null&&User[Field]!==undefined)
        {
            TestValues[Field] = UserCopy[Field];
            delete UserCopy[Field];
        }
    });
    if(Object.keys(TestValues).length > 0)
    {
        GetUser.call(Self, UserCopy, function(Err, UserInfo) {
            HandleError(Err, Callback, function() {
                if(UserInfo)
                {
                    VerifyHashableRecur.call(Self, TestValues, UserInfo, Callback);
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

function PromiseCallback(Fulfill, Reject)
{
    return(function(Err, Result) {
        if(Err)
        {
            Reject(Err);
        }
        else
        {
            Fulfill(Result);
        }
    });
}

function UserStore(DB, FieldsSchema, Callback, Options)
{
    //Reshuffle arguments properly if the Callback is not specified due ot promises
    if(typeof(arguments[2]) !== 'function')
    {
        var Options = arguments[2];
        var Callback = null;
    }
    
    if(this instanceof UserStore) //Inside the constructor, this is called internally
    {
        this.DB = DB;
        this.KeyLength = Options && Options.KeyLength ? Options.KeyLength : 20;
        this.Iterations = Options && Options.Iterations ? Options.Iterations : 10000;
        this.Hash = Options && Options.Hash ? Options.Hash : GenerateHashFunction(this.KeyLength, this.Iterations);
        this.Verify = Options && Options.Verify ? Options.Verify : GenerateVerifyFunction(this.KeyLength, this.Iterations);
        this.CollectionName = Options && Options.CollectionName ? Options.CollectionName : 'Users';
        this.MembershipsArray = Options && Options.MembershipsArray ? Options.MembershipsArray : true;
        var HashOnly = Options && Options.HashOnly ? Options.HashOnly : null;
        
        var Indices = Options && Options.Indices ? Options.Indices : [];
        this.NotNull = FieldsSchema.List('Required', true);
        var UniquesRegular = UserProperties.ListIntersection(FieldsSchema.List('Unique', true), FieldsSchema.List('Required', true));
        var UniquesSparse = UserProperties.ListIntersection(FieldsSchema.List('Unique', true), FieldsSchema.List('Required', false));
        UniquesRegular.forEach(function(Field) {
            var NewIndex = {'Fields': {}, 'Options': {'unique': true}};
            NewIndex['Fields'][Field]=1;
            Indices.push(NewIndex);
        });
        UniquesSparse.forEach(function(Field) {
            var NewIndex = {'Fields': {}, 'Options': {'unique': true, 'sparse': true}};
            NewIndex['Fields'][Field]=1;
            Indices.push(NewIndex);
        });
        
        this.Hashable = FieldsSchema.ListHashable();
        if(HashOnly)
        {
            this.Hashable = UserProperties.ListIntersection(this.Hashable, HashOnly);
        }
        
        EnsureDependencies.call(this, Indices, (function(Err) {
            Callback(Err, this);
        }).bind(this));
    }
    else
    {
        //If no callback specified, wrap constructor in promise
        if(!Callback)    
        {
            return new Promise(function(Fulfill, Reject) {
                new UserStore(DB, FieldsSchema, PromiseCallback(Fulfill, Reject), Options);
            });
        }

        return new UserStore(DB, FieldsSchema, Callback, Options);
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
                if(Err && Err.name && Err.name=='MongoError' && Err.code && (Err.code === 11001 || Err.code === 11000))
                {
                    AugmentError(Err, 'ConstraintError', 'Unique');
                }
                if(Result && Result.ops)    //Necessary for external consistancy when using the 2.x.x mongodb driver
                {
                    Result = Result.ops; 
                }
                Callback(Err, Result);
            });
        });
    });
}

UserStore.prototype.Add = function(User, Callback) {
    var Self = this;
    
    //If no callback specified, wrap call in promise
    if(!Callback)
    {
        return new Promise(function(Fulfill, Reject) {
            Self.Add(User, PromiseCallback(Fulfill, Reject));
        });
    }

    if(!EnforceNotNull.call(Self, User))
    {
        var NotNullError = new Error('UserStore: NotNull constraint not respected.');
        NotNullError.name = 'ConstraintError';
        AugmentError(NotNullError, 'ConstraintError', 'NotNull');
        Callback(NotNullError);
        return;
    }
    HashHashable.call(Self, User, function(Err, UserCopy) {
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
                if(Result && Result.result)    //Necessary for external consistancy when using the 2.x.x mongodb driver
                {
                    Result = Result.result.n; 
                }
                Callback(Err, Result);
            });
        });
    });
}

UserStore.prototype.Remove = function(User, Callback) {
    var Self = this;
    
    //If no callback specified, wrap call in promise
    if(!Callback)
    {
        return new Promise(function(Fulfill, Reject) {
            Self.Remove(User, PromiseCallback(Fulfill, Reject));
        });
    }
    
    VerifyHashable.call(this, User, function(Err, Ok, UserInfo) {
        HandleError(Err, Callback, function() {
            if(!Ok)
            {
                Callback(null, 0);
            }
            else
            {
                if(UserInfo) //If UserInfo is set, hashable fields were present in User and UserInfo containts the properly hashed values
                {
                    User = UserInfo;
                }
                RemoveUser.call(Self, User, Callback);
            }
        });
        
    });
};

UserStore.prototype.Get = function(User, Callback) {
    var Self = this;
    
    //If no callback specified, wrap call in promise
    if(!Callback)
    {
        return new Promise(function(Fulfill, Reject) {
            Self.Get(User, PromiseCallback(Fulfill, Reject));
        });
    }
    
    VerifyHashable.call(this, User, function(Err, Ok, UserInfo) {
        HandleError(Err, Callback, function() {
            if(!Ok)
            {
                Callback(null, null);
            }
            else
            {
                if(UserInfo) //If UserInfo is set, hashable fields were present in User and UserInfo containts the properly hashed values
                {
                    Callback(null, UserInfo);
                }
                else //If hashable fields are not present in User
                {
                    GetUser.call(Self, User, Callback);
                }
            }
        });
    });
};

UserStore.prototype.Count = function(User, Callback) {
    var Self = this;
    
    //If no callback specified, wrap call in promise
    if(!Callback)
    {
        return new Promise(function(Fulfill, Reject) {
            Self.Count(User, PromiseCallback(Fulfill, Reject));
        });
    }
    
    CountUser.call(Self, User, Callback);
};

UserStore.prototype.AddMembership = function(User, Membership, Callback) {
    var Self = this;
    
    //If no callback specified, wrap call in promise
    if(!Callback)
    {
        return new Promise(function(Fulfill, Reject) {
            Self.AddMembership(User, Membership, PromiseCallback(Fulfill, Reject));
        });
    }
    
    this.DB.collection(this.CollectionName, function(Err, UsersCollection) {
        HandleError(Err, Callback, function() { 
            VerifyHashable.call(Self, User, function(Err, Ok, UserInfo) {
                HandleError(Err, Callback, function() {
                    if(Ok)
                    {
                        if(UserInfo)
                        {
                            User = UserInfo;
                        }
                        UsersCollection.update(User, {'$addToSet': {'Memberships': Membership}}, function(Err, Result) {
                            if(Result && Result.result)    //Necessary for external consistancy when using the 2.x.x mongodb driver
                            {
                                Result = Result.result.n; 
                            }
                            Callback(Err, Result);
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

UserStore.prototype.RemoveMembership = function(User, Membership, Callback) {
    var Self = this;
    
    //If no callback specified, wrap call in promise
    if(!Callback)
    {
        return new Promise(function(Fulfill, Reject) {
            Self.RemoveMembership(User, Membership, PromiseCallback(Fulfill, Reject));
        });
    }
    
    this.DB.collection(this.CollectionName, function(Err, UsersCollection) {
        HandleError(Err, Callback, function() {
            VerifyHashable.call(Self, User, function(Err, Ok, UserInfo) {
                HandleError(Err, Callback, function() {
                    if(Ok)
                    {
                        if(UserInfo)
                        {
                            User = UserInfo;
                        }
                        UsersCollection.update(User, {'$pull': {'Memberships': Membership}}, function(Err, Result) {
                            if(Result && Result.result)    //Necessary for external consistancy when using the 2.x.x mongodb driver
                            {
                                Result = Result.result.n; 
                            }
                            Callback(Err, Result);
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

function Update(Self, User, Updates, Membership, Get, Callback) {
    if(!EnforceNotNullUpdates.call(Self, Updates, true))
    {
        var NotNullError = new Error('UserStore: NotNull constraint not respected.');
        NotNullError.name = 'ConstraintError';
        AugmentError(NotNullError, 'ConstraintError', 'NotNull');
        Callback(NotNullError);
        return;
    }
    HashHashable.call(Self, Updates, function(Err, UpdatesCopy) {
        HandleError(Err, Callback, function() {
            VerifyHashable.call(Self, User, function(Err, Ok, UserInfo) {
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
                                if(Membership)
                                {
                                    if(Membership.Add)
                                    {
                                        if(Array.isArray(Membership.Add))
                                        {
                                            UpdateObject['$addToSet'] = {'Memberships': {'$each': Membership.Add}};
                                        }
                                        else
                                        {
                                            UpdateObject['$addToSet'] = {'Memberships': Membership.Add};
                                        }
                                    }
                                    else if(Membership.Remove)
                                    {
                                        if(Array.isArray(Membership.Remove))
                                        {
                                            UpdateObject['$pullAll'] = {'Memberships': Membership.Remove};
                                        }
                                        else
                                        {
                                            UpdateObject['$pull'] = {'Memberships': Membership.Remove};
                                        }
                                    }
                                }
                                if(HasHashable(User, Self.Hashable))
                                {
                                    var UserCopy = SurfaceCopy(User);
                                    ClearHashable(UserCopy, Self.Hashable);
                                }
                                else
                                {
                                    var UserCopy = User;
                                }
                                if(!Get)
                                {
                                    UsersCollection.update(UserCopy, UpdateObject, function(Err, Result) {
                                        if(Err && Err.name && Err.name=='MongoError' && Err.code && (Err.code === 11001 || Err.code === 11000))
                                        {
                                            AugmentError(Err, 'ConstraintError', 'Unique');
                                        }
                                        if(Result && Result.result)    //Necessary for external consistancy when using the 2.x.x mongodb driver
                                        {
                                            Result = Result.result.n; 
                                        }
                                        Callback(Err, Result);
                                    });
                                }
                                else
                                {
                                    if(UsersCollection.findOneAndUpdate) //Method on 2.x.x mongodb driver, much faster than findAndModify
                                    {
                                        UsersCollection.findOneAndUpdate(UserCopy, UpdateObject, {'returnOriginal': false}, function(Err, Result) {
                                            if(Err && Err.name && Err.name=='MongoError' && Err.code && (Err.code === 11001 || Err.code === 11000))
                                            {
                                                AugmentError(Err, 'ConstraintError', 'Unique');
                                            }
                                            if(Result && Result.value !== undefined)
                                            {
                                                Result = Result.value; 
                                            }
                                            Callback(Err, Result);
                                        });
                                    }
                                    else
                                    {
                                        UsersCollection.findAndModify(UserCopy, [['_id', 1]], UpdateObject, {'new': 1}, function(Err, Result) {
                                            if(Err && Err.name && Err.name=='MongoError' && Err.code && (Err.code === 11001 || Err.code === 11000))
                                            {
                                                AugmentError(Err, 'ConstraintError', 'Unique');
                                            }
                                            Callback(Err, Result);
                                        });
                                    }
                                }
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
}

UserStore.prototype.UpdateAtomic = function(User, Updates, Memberships, Callback) {
    var Self = this;
    
    //If no callback specified, wrap call in promise
    if(!Callback)
    {
        return new Promise(function(Fulfill, Reject) {
            Update(Self, User, Updates, Memberships, false, PromiseCallback(Fulfill, Reject));
        });
    }
    
    Update(Self, User, Updates, Memberships, false, Callback);
}

UserStore.prototype.UpdateGetAtomic = function(User, Updates, Memberships, Callback) {
    var Self = this;
    
    //If no callback specified, wrap call in promise
    if(!Callback)
    {
        return new Promise(function(Fulfill, Reject) {
            Update(Self, User, Updates, Memberships, true, PromiseCallback(Fulfill, Reject));
        });
    }
    
    Update(Self, User, Updates, Memberships, true, Callback);
}

UserStore.prototype.Update = function(User, Updates, Callback) {
    var Self = this;
    
    //If no callback specified, wrap call in promise
    if(!Callback)
    {
        return new Promise(function(Fulfill, Reject) {
            Update(Self, User, Updates, null, false, PromiseCallback(Fulfill, Reject));
        });
    }
    
    Update(Self, User, Updates, null, false, Callback);
};

UserStore.prototype.UpdateGet = function(User, Updates, Callback) {
    var Self = this;
    
    //If no callback specified, wrap call in promise
    if(!Callback)
    {
        return new Promise(function(Fulfill, Reject) {
            Update(Self, User, Updates, null, true, PromiseCallback(Fulfill, Reject));
        });
    }
    
    Update(Self, User, Updates, null, true, Callback);
}

UserStore.prototype.UnitTests = {};
UserStore.prototype.UnitTests['GenerateVerifyFunction'] = GenerateVerifyFunction;
UserStore.prototype.UnitTests['GenerateHashFunction'] = GenerateHashFunction;
UserStore.prototype.UnitTests['EnsureDependencies'] = EnsureDependencies;
UserStore.prototype.UnitTests['EnforceNotNull'] = EnforceNotNull;
UserStore.prototype.UnitTests['HandleError'] = HandleError;

module.exports = UserStore;
