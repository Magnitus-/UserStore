User-Store
==========

Generic storage for user accounts that is meant to be flexible and provide a minimalistic default interface.

It has barebone optional built-in facilities to handle roles and hashing.

Requirements
============

- A recent version of MongoDB (initially developped on 2.49, now developped on 3.07)

- node.js 0.1x or later

- npm if you want the easy way to install this module.

mongodb Driver Support
----------------------

currently, both 1.4.x and 2.x.x versions of the mongodb project are supported: slight manipulations are done on the results of calls to the 2.x.x version to make them consistent with 1.4.x (which is ultimately better I find as the results from calls to 1.4.x are less database specific which makes this library more easily portable to another database).

I personality would like to start using solely version 2.x.x of the driver for my projects as soon as possible, so with this in mind, version 1.4.x will be supported for this library as long as:

- I can do so while still supporting the latest version of mongodb and not have to put version agnostic wrappers around driver calls
- 1.4.x support doesn't limit features to this library

Installation
============

npm install user-store

Running Tests
=============

In the directory where the module is located, run the following 2 commands on the prompt:

- npm install
- npm test

If you run the tests with superuser privileges, tests for connection failure will also run (in Linux). Note that those tests will render your MongoDB process unresponsive at various points during the tests.

Overall Concept
===============

This module makes use of MongoDB's shema-free design and the user-properties library to be unbiased about what information you store for your users and what information you use to identify them.

Is uses a basic Add/Get/Update/Remove/Count methods to manipulate users. Additionally, AddMembership and RemoverMembership methods are provided to operate on a user's Memberships set in order to abstract away MongoDB's set manipulation.

All its functions take a &lt;User&gt; object as an argument that you can defined with whichever custom fields you want (ex: Username, Email, FistName, LastName, etc).

The only special field is 'Memberships' (which is returned for the 'Get' accessor and contain memberships).

user-properties
===============

From version 2.0.0 onward, user-store uses a user-properties schema passed to the constructor to define non-null and unique constraints as well as which fields are hashed.

Each category is defined as follows, with 'FieldsSchema' being the user schema passed to the user-store constructor:

- Not Null fields: FieldsSchema.List('Required', true)
- Uniquely indexed fields: UserProperties.ListIntersection(FieldsSchema.List('Unique', true), FieldsSchema.List('Required', true))
- Uniquely, sparsely indexed fields: UserProperties.ListIntersection(FieldsSchema.List('Unique', true), FieldsSchema.List('Required', false))
- Hashed fields: FieldsSchema.ListHashable()

See the user-properties project (also found on npm) for details.

As before, you can specify additional joint and other custom indexes using the 'Indices' option. Additionally, you can also restrict which fields are hashed (beyond the default presented above) by using the 'HashOnly' option.

More details about those options can be found below.

Constructor
===========

The constructor for the user-store module has the following signature:

function(&lt;DB&gt;, &lt;UserSchema&gt;, &lt;Callback&gt;, &lt;Options&gt;)

A barebone call to this function would look like this:

```javascript
var Mongodb = require('mongodb');
var UserStore = require('user-store');
var UserProperties = require('user-properties');

//Probably some code

var UserSchema = UserProperties({
    'Username': {
        'Required': true,
        'Unique': true,
        'Mutable': false,
        'Description': function(Value) {return (typeof(Value)!='undefined')&&Verifications['Username'].test(Value)}
    },
    'Email': {
        'Required': true,
        'Unique': true,
        'Privacy': UserProperties.Privacy.Private,
        'Description': function(Value) {return (typeof(Value)!='undefined')&&Verifications['Email'].test(Value)}
    },
    'Password': {
        'Required': true,
        'Privacy': UserProperties.Privacy.Secret,
        'Retrievable': false,
        'Description': function(Value) {return (typeof(Value)!='undefined')&&Verifications['Password'].test(Value)},
        'Sources': ['User', 'Auto'],
        'Generator': function(Callback) {Callback(null, Uid(15));}
    },
    'EmailToken': {
        'Required': true,
        'Privacy': UserProperties.Privacy.Secret,
        'Retrievable': false,
        'Access': 'Email',
        'Sources': ['Auto'],
        'Generator': function(Callback) {Callback(null, Uid(20));}
    }});

MongoDB.MongoClient.connect("mongodb://localhost:27017/SomeDatabase", {native_parser:true}, function(Err, DB) { //Your code will probably differ here
    UserStore(Context['DB'], UserSchema, function(Err, Store) {
    
    //Do stuff with the Store instance
    
    });
});
```

- &lt;DB&gt;: Is the database handle generated by Node's MongoDB driver that you are passing to the user store to operate on the desired database.

- &lt;UserSchema&gt;:

See the user-properties section above for details on this argument.

- &lt;Callback&gt;:

&lt;Callback&gt; is a function that takes the following signature: function(&lt;Err&gt;, &lt;Store&gt;)

&lt;Err&gt; is defined if there was an error and &lt;Store&gt; is the user-store instance that you can call methods on to access or manipulate users.

- &lt;Options&gt;:

It is an object containing various options you can set for the user-store instance (they all have defaults so it can be omitted).

The options are as follow:

-CollectionName: The collection name that the user-store instance will use to store/manipulate users. It defaults to 'Users'.

-MembershipsArray: 

If set to true (default), an empty array ([]) will automatically be added to the Memberships property of all users generated with the Add method.

This is a convenience method to provide a unified feel when retrieving users. Without it, the Memberships property will be undefined for users until the AddMembership method is first call for that user.

If you do not plan on using the memberships API of user-store, you can set this to false.

-KeyLength:

Length of the hashed passwords if the default hashing is used. Greater lengths Defaults to 20.

-Iterations:

Correlates to the time it will take to hash using the default hashing algorithm. Greater values will make stored passwords harder to brute-force if you user store gets stolen (assume it will), but will take more time to process.

The greatest value you can manage given your expected traffic and server hardware is preferable. 

It defaults to 10000.

-Hash,Verify:

Those options should be defined together and override the default password hash facility with a custom one (useful for those wishing to use bcrypt for example).

'Hash' takes the following signature: function(&lt;Password&gt;, &lt;Callback&gt;)

Here, &lt;Password&gt; is a plaintext password and &lt;Callback&gt; is called once hashing is completed and expects an error object (if any else null) as its first argument and the hashed password as its second.

'Verify' takes the following signature: function(&lt;Password&gt;, &lt;Hash&gt;, &lt;Callback&gt;)

Here, &lt;Password&gt; is the plaintext password to verify, &lt;Hash&gt; is the hashed password to verify the plaintext against and &lt;Callback&gt; is called once the verification is complete and expects an error object (if any else null) as its first argument and a boolean indicating whether or not the password matched as its second.

Ex:

```javascript
//Custom bcrypt implementation taken directly from the tests
var Bcrypt = require('bcrypt');

//Probably some code

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

//More code

var StoreOptions = {'Hash': BcryptHash, 'Verify': BcryptVerify};

UserStore(SomeDBHandle, SomeRestrictions, function(Err, Store) {
    //Hopefully some code here
}, StoreOptions);

```

-Indices: Contains an array of custom indices that you may wish to define on the Users collection. It takes the following form:

[&lt;Index1&gt;, &lt;Index2&gt;, etc], where &lt;Indexi&gt; takes the following form:

{'Fields': &lt;Fields&gt;, 'Options': &lt;Options&gt;}, where &lt;Fields&gt; and &lt;Options&gt; correspond to the arguments you would pass to an 'ensureIndex' call on a 'collection' object using the native MongoDB driver. 

ex:

```javascript
//Some code here

//Assume we live in a world were the combination of a person's first name and family name uniquely identifies him

var StoreOptions = {};
StoreOptions['Indices'] = [{'Fields': {'FirstName': 1, 'LastName': 1}, 'Options': {'unique': true}}];

UserStore(SomeDBHandle, UserSchema, function(Err, Store) {

//Hopefully some code here

}, StoreOptions);

```

-HashOnly: Specifies an array of fields to narrow down the list of fields that user-store will look at for hashing. Useful when you have some fields that are viable candidate for hashing that you do not want hashed.

If the above option is defined, user-store does the following operation to get the final list of fields that will be hashed: UserProperties.ListIntersection(UserSchema.ListHashable(), HashOnly)


Instance Methods
================

Add
---

Method to add users. It has the following signature: function(&lt;User&gt;, &lt;Callback&gt;)

&lt;User&gt; is an object that contains the fields that define your user (ex: Email, Username, Password, etc). If any hashed field is present, it will be hashed internally (either by the default hashing method or a custom one you passed in the constructor).

Also, if you plan on using the membership API, 'Memberships' shouldn't be defined in <User> (the library will take care of that for you).

&lt;Callback&gt; will have an error as its first arguments and the result as its second (which is an array containing generated users).

Ex:

```javascript
//Some code

Store.Add({'Email': 'SomeEmail@email.com', 'Username': 'SomeUser', 'Password': 'qwerty!'}, function(Err, Result) {

    if(Err)
    {
        if(Err.UserStore && Err.UserStore.Name == 'ConstraintError')
        {
            if(Err.UserStore.Type == 'NotNull')
            {
                //NotNull constraint violation, handle it
            }
            else
            {
                //Unique constraint violation, handle it
            }
        }
        else
        {
            //Some other database error occured
        }
    }
    else if(Result.length==1)
    {
        //User was successfully created, yay!
    }

});

```

Note: While the NotNull and Unique restrictions will cause an error to be returned if those properties are not respected during insertion, the returned error will have the following properties:

- UserStore.Name: Will have the value 'ConstraintError'.

- UserStore.Type: will have the value 'NotNull' or 'Unique', depending on which constraint was not respected.

Checking for the existence of the 'UserStore' property in the error object with the above values is an easy way to separate constraint-caused errors from system errors.

Get
---

Method to get a specific user. It has the following signature: function(&lt;User&gt;, &lt;Callback&gt;)

&lt;User&gt; is an object that only needs to contain the right fields to uniquely identify your user. If any hashable fields are present, they will be hashed internally and used to authenticate the user.

&lt;Callback&gt; will have an error as its first argument and the users as its second (if it was sucessfully retried, else null).

Ex:

```javascript
//Some code

//Here, we pass a plaintext password so we expect successful authentication in order to retrieve the user 
//This might get called on behalf of a user trying to login.
Store.Get({'Email': 'SomeEmail@email.com', 'Password': 'password!'}, function(Err, User) {
    if(Err)
    {
        //Some error occured, handle it. Probably the database.
    }
    else if(User)
    {
        //User successfully retrieved. 
    }
    else
    {
        //User was not successfully retrieved. Probably a wrong email or wrong password
    }
});
```

```javascript
//Some code

//Here, we don't pass a password so we don't expect authentication to retrieve the user.
//Maybe we perform authentication elsewhere using another method or maybe we are retrieving user information from an admin panel.

Store.Get({'Email': 'SomeEmail@email.com'}, function(Err, User) {
    if(Err)
    {
        //Some error occured, handle it. Probably the database.
    }
    else if(User)
    {
        //User successfully retrieved. 
    }
    else
    {
        //User was not successfully retrieved. Probably a wrong email.
    }
});

```

Remove
------

Method to delete one or more users. It has the following signature: function(&lt;User&gt;, &lt;Callback&gt;)

&lt;User&gt; is an object that only needs to contain the right fields to identify the user(s) we want to delete. If any hashable fields are present, they will be hashed internally and used to authenticate the user.

&lt;Callback&gt; will have an error as its first argument and the number of deleted users as its second.

Ex:

```javascript
//Some code

//Here, we pass a plaintext password so we expect successful authentication in order to delete the user 
//This might get called on behalf of a user trying to delete his account.
Store.Remove({'Email': 'SomeEmail@email.com', 'Password': 'password!'}, function(Err, Result) {
    if(Err)
    {
        //Some error occured, handle it. Probably the database.
    }
    else if(Result==1)
    {
        //User was successfully deleted.
    }
    else if(Result==0)
    {
        //User was not successfully deleted. Probably a wrong email or wrong password
    }
});
```

```javascript
//Some code

//Here, we pass a plaintext password is not provided so authentication is not performed.
//This might get called on behalf of an administrator using an admin panel or a user that was authenticated with another method.
Store.Remove({'Email': 'SomeEmail@email.com'}, function(Err, Result) {
    if(Err)
    {
        //Some error occured, handle it. Probably the database.
    }
    else if(Result==1)
    {
        //User was successfully deleted.
    }
    else if(Result==0)
    {
        //User was not successfully deleted. Probably a wrong email.
    }
});
```

Update
------

Method to update one user. It has the following signature: function(&lt;User&gt;, &lt;Updates&gt;, &lt;Callback&gt;)

&lt;User&gt; is an object that only needs to contain the right fields to identify the user(s) we want to update. If any hashable fields are defined, they will be hashed internally and used to authenticate the user.

&lt;Updates&gt; is an object that only needs to contain the fields you want to update (if they don't exist, they will be created). If any hashable fields are present, they will be hashed internally before storage just like in user creation.

&lt;Callback&gt; will have a callback as its first argument and the number of updated users as its second.

Ex:

```javascript
//Some code

//Here, we pass a plaintext password so we expect successful authentication in order to update the user 
//This might get called on behalf of a user trying to change his password
Store.Update({'Email': 'SomeEmail@email.com', 'Password': 'password!'}, {'Password': 'SlightlyBetterPassword!'}, function(Err, Result) {
    if(Err)
    {
        //Some error occured, handle it. Probably the database.
    }
    else if(Result==1)
    {
        //User was successfully updated
    }
    else if(Result==0)
    {
        //User was not successfully updated. Probably a wrong email or wrong password
    }
});
```

```javascript
//Some code

//Here, we pass a plaintext password is not provided so authentication is not performed.
//This might get called on behalf of an administrator modifying the user from an admin panel
Store.Update({'Email': 'SomeEmail@email.com'}, {'Credits': 100}, function(Err, Result) {
    if(Err)
    {
        //Some error occured, handle it. Probably the database.
    }
    else if(Result==1)
    {
        //User was successfully updated
    }
    else if(Result==0)
    {
        //User was not successfully updated. Probably a wrong email.
    }
});
```

AddMembership
-------------

This function is called to add a group/role to a user. Internally, a set operator is used so the same group/role can't be added multiple times redundantly with this call.

The method has the following signature: function(&lt;User&gt;, &lt;Membership&gt;, &lt;Callback&gt;)

&lt;User&gt; should contain the necessary fields to uniquely identify the user(s) being operated on. If any hashed fields are present, they will be hashed internally and used to authentify the user.

&lt;Membership&gt; should correspond to the membership being added.

&lt;Callback&gt; will have a callback as its first argument and the number of updated users as its second.

Ex:

```javascript

//Some code

Store.AddMembership({'Email': 'SomeEmail@email.com'}, 'Banned', function(Err, Result) {
   if(Err)
   {
       //Probably a database error
   }
   else if(Result==1)
   {
       //User successfully banned
   }
   else if(Result==0)
   {
       //Wrong email maybe?
   }
});
```

RemoveMembership
----------------

This function is called to remove a group/role from a user.

The method has the following signature: function(&lt;User&gt;, &lt;Membership&gt;, &lt;Callback&gt;)

&lt;User&gt; should contain the necessary fields to uniquely identify the user(s) being operated on. If any hashed fields are present, they will be hashed internally and used to authentify the user.

&lt;Membership&gt; should correspond to the membership being removed.

&lt;Callback&gt; will have a callback as its first argument and the number of updated users as its second.

Ex:

```javascript

//Some code

Store.RemovedMembership({'Email': 'SomeEmail@email.com'}, 'Banned', function(Err, Result) {
   if(Err)
   {
       //Probably a database error
   }
   else if(Result==1)
   {
       //Ban successfully lifted
   }
   else if(Result==0)
   {
       //Wrong email maybe?
   }
});
```

Count
-----

Method to count the number of users matching specific criteria. It has the following signature: function(&lt;User&gt;, &lt;Callback&gt;)

&lt;User&gt; is an object that should contain all the criteria that defines users you want to count. If 'Password' is defined, it will not be hashed (leading to 0 result by default). 

This is a pratical consideration as a sane password storage implementation (including the default in this library) will include salted hashing and matching a password again several documents using such a scheme would involve fetching all documents that match the other criteria and then doing a document-by-document comparison for the password using the salt of each document.

Depending on the number of documents that match the other criteria and whether or not the hashing algorithmn is effective against computers matching the specs of your server, this could prove to be an incredibly slow call to make.

&lt;Callback&gt; will have an error as its first argument and the count as the second (if no error was encountered).

Ex:

```javascript
//Some code

Store.Count({'Country': 'Canada'}, function(Err, Count) {
    if(Err)
    {
        //Some error occured, handle it. Probably the database.
    }
    else if(Count>0)
    {
        //Some of our users are Canadian
    }
    else
    {
        //No Canadian users, what a boring web site!
    }

});

```

UpdateAtomic
------------

This method is similar to the 'Update' method, but also allows the caller to either add or remove multiple groups to the user's Memberships property.

Both actions are done in one atomic operation.

It has the following signature: function(&lt;User&gt;, &lt;Updates&gt;, &lt;Memberships&gt;, &lt;Callback&gt;)

All arguments except 'Memberships' have the same meaning as with the 'Update' method (and 'Callback' has the same signature).

'Memberships' is an object that can either contain the key 'Add' or 'Remove' (if it contains both, only 'Add' will be taken into account).

The 'Add'/'Remove' property of the 'Memberships' object can be assigned either a string (representing a single group to add/remove) or an array of strings (representing multiple groups to add/remove). If multiple groups are selected, they are all added/removed in a single atomic operation along with the update.

Ex1:

```javascript
//Some code

//Using UpdateAtomic to ban a cheater and set his score to 0 in one atomic operation
Store.UpdateAtomic({'Username': 'Cheater666'}, {'Score': 0}, {'Add': 'Banned'}, function(Err, Result) {
    if(Err)
    {
        //Some error occured, handle it. Probably the database.
    }
    else if(Result==1)
    {
        //User was successfully updated
    }
    else if(Result==0)
    {
        //User was not successfully updated. Probably a wrong Username.
    }

});

```

Ex2:

```javascript
//Some code

//Using UpdateAtomic to mark the departure of an employee with admin privileges
Store.UpdateAtomic({'Name': 'Adrian'}, {'DepartureDate': Now}, {'Remove': ['Admin', 'Ops']}, function(Err, Result) {
    if(Err)
    {
        //Some error occured, handle it. Probably the database.
    }
    else if(Result==1)
    {
        //User was successfully updated
    }
    else if(Result==0)
    {
        //User was not successfully updated. Probably a wrong Name.
    }

});

```

UpdateGet & UpdateGetAtomic
---------------------------

Behave simiarly to Update and UpdateAtomomic, but return the newly updated user (as an object) as the callback's second argument instead of the number of updated user (ie, 0 or 1).

If no user is updated, null is returned as the callback's second argument instead.

These methods perform the update and get atomically.

Performance note: 

For the version 1.4.x of the mongodb driver, these methods call 'findAndModify' on the collection which makes them significantly slower than calling the 'Update' or 'UpdateAtomic' method (which calls 'update' on the collection), followed by the 'Get' method ( which calls 'findOne' on the collection).

So if atomicity of the Update and Get are not required, you'll get a better performance by calling them separately (ie, call to Update/UpdateAtomic followed by call to Get) rather than use UpdateGet/UpdateGetAtomic.

For the version 2.x.x of the mongodb driver, the newly available (and much faster) 'findOneAndUpdate' is called on the collection instead, making this method slightly faster than separates Update & Get and atomic to boot (and thus, always preferable).

So in short, if you need to update a user and get his info:

- If you use version 1.4.x of the mongodb driver and don't need atomicity between the updating of a user's profile and its fetching, use Update or UpdateAtomic followed by Get.

- If you need atomicity between the updating of a user's profile and its fetching or if you are using version 2.x.x of the mongodb driver, use UpdateGet/UpdateGetAtomic.

Promises Support
================

From version 2.2.0 onward, all calls to user-store methods will return a promise if a callback is not passed in the method's arguments.

Calling the methods this way requires a standard compliant promise implementation to be accessible via a global Promise variable.

I ran the tests for the library against the bluebird implementation of promises.

Ex:

```javascript
global.Promise = require('bluebird');
var Mongodb = require('mongodb');
var UserStore = require('user-store');
var UserProperties = require('user-properties');

//Some code to define the User schema and store options, see constructor doc for details

var Store = null;
//Here, I will instanciate a store, create a new user, update his profile and count him
MongoDB.MongoClient.connect("mongodb://localhost:27017/SomeDatabase", {native_parser:true}, function(Err, DB) {
    UserStore(DB, UserSchema, StoreOptions).then(function(StoreInstance) {                      //Promise returning call
        Store = StoreInstance;                                                                  //We need this, because we don't have the free closure we get with embedded callbacks
        return Store.Add({'Username': 'Robert', 'Email': 'robert@fakemail.com', 'Age': 35});    //Promise returning call
    }).then(function(Result) {
        console.log(Result.length);    //logs 1
        return Store.Update({'Username': 'Robert'}, {'Age': 25});                               //Promise returning call
    }).then(function(Result) { 
        console.log(Result);    //logs 1
        return Store.Count({'Age': 25});                                                        //Promise returning call
    }).then(function(Count) {
        console.log(Result);    //logs 1
        return Result;
    }).catch(function(Err) {
        console.log(Err);       //Some error that occured during one of the calls
    });
});

```

Version History
===============

2.4.3
-----

- Fixed another case of constrain violations not being reported for version 1.4.x of the mongodb driver
- Fixed setup of non-responsive tests not working properly for version 2.x.x of the mongodb driver

2.4.2
-----

Fixed bug where unique constraint violations would not be reported for version 1.4.x of the mongodb driver due to the unique error format of the findAndModify method.

2.4.1
-----

- Fixed a crash bug when violating Unique constraint with UpdateGet or UpdateGetAtomic.
- Added tests for the above.

2.4.0
-----

- Added UpdateGet and UpdateGetAtomic methods.
- Corrected erronous information for the documentation of the 'Update' method.

2.3.0
-----

- Added support for version 2.x.x of mongodb
- Changed the mongodb dependency to convey the range of supported versions.

2.2.0
-----

- Added bluebird as a dev dependency
- Added Promise support
- Adjusted tests so they don't crash anymore with version 2.x.x of mongodb (though currently, 30/111 of tests fail with version 2.x.x of the driver so the library isn't 2.x.x compatible yet)

2.1.0
-----

Added UpdateAtomic method.

2.0.4
-----

Added tests for error handling when connection is terminated.

2.0.3
-----

Change user-properties depedency to include the right range of supported versions.

2.0.2
-----

Updated version of user-properties dependency

2.0.1
-----

Removed dangling nimble module request in library

2.0.0
-----

- Added user-properties as a dependency to this project
- Replaced the Restrictions parameter by a user-properties instance
- Replaced default hashing of 'Password' field by hashing of fields returned by the ListHashable method of user-properties
- Added HashOnly option to constructor
- Added hash verification for Memberships methods
- Bit of refactoring

1.3.0
-----

- Added properties to the error passed to the callback of the 'Update' method if the cause is a restriction (ie, Unique or NotNull) to more easily differentiate those from system errors.
- Fixed a bug where user could update fields with non-null constraint to null.

1.2.1
-----

Updated mongodb dependency to version 1.4.35.

1.2.0
-----

- Added Count method.
- Updated mongodb dependency to version 1.4.30.

1.1.1
-----

Updated mongodb dependency to version 1.4.29.

1.1.0
-----

Added properties to the error passed to the callback of the 'Add' method if the cause is a restriction (ie, Unique or NotNull) to more easily differentiate those from system errors.


1.0.1
-----

- Removed some dated misleading comments in the code.
- Completed doc
- For default hash, changed default KeyLength from 512 to 20 and Iterations from 1000 to 10000.

1.0.0
-----

Initial release
