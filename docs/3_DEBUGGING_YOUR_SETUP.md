PDSs are part of a distributed system with many different actors and services interacting with each other. That fundamentally means that many many things can go wrong. If you're having issues like Bluesky not picking up your posts then it's time to get your debugging hands dirty! Below is some general debugging advies as well as a list of frequent issues, how to spot them and how to fix them. If you belive your issue isn't listed below don't be afraid to contact us! We're more than willing to help if we can. Our official account is @tranquil.farm and we are additionally both available in the tangled discord in our "guest" channel (tysm tangled!) or in the atproto-touchers (somewhat less frequently however).

> As always: TAKE BACKUPS!!
> View the note on backups at the bottom of "Welcome to Tranquil PDS".

# General
As always debugging starts with good tools for investigating what is going wrong. For atproto those tools are primarily <pdsls.dev> and <debug.hose.cam>. They are your friends! Get acquainted with them.

PDSls is (as the name implies) good for debugging the PDS side of things: is your PDS up? accessible to the outside world (or at least your PC)? what does the firehose coming from your PDS look like? but also other account level details: is your handle valid? what are your current rotation keys? signing key? etc.

debug.hose.cam is wonderful to get your an overview of what the relay side of things looks like. Open it up and type in a handle, DID or PDS URL and it'll quickly fetch a bunch of useful debug info for you.

# `seq` from PDS is behind `seq` stored by relays.
This is one of the less common sources of issues but a real head scratcher if you don't know to look out for it. This is generally recognisible by no changes you take propagating to the network and all the relays showing your PDS as `idle` when you look at debug.hose.cam. That last one especially is a tell tale sign!!

Fixing this isn't too hard. You want to figure out what `seq` the relays think your PDS is at, the easiest way to do this is dig through your browser devtools network tab and find the `com.atproto.sync.getHostStatus` calls for each relay and find the `seq` in the response.

> 🌺 Nel
>
> #protip double check that the `seq` is actually misaligned with your PDS by getting the latest `seq` from your PDS using PDSls's firehose feature and a cursor value of `0` when connecting. If the relays don't have a `seq` that's bigger than your PDSs `seq` then this isn't your issue!

Now you need to update the PDS to use a `seq` that's *at least* one above the highest `seq` any of the relays have. Currently doing this on Tranquil depends on your used storage backend. For the default Postgres repo store you want to shutdown Tranquil itself, open the DB in `psql` and run `SELECT setval('firehose_seq, <new updated seq value>');` and the start Tranquil back up. Take a few actions to make sure new events get sent out. Everything should work once all the downstream consumers have had a chance to resync. You can double check with debug.hose.cam that all the relays show your PDS as `active`. Some might need a lil push with a request crawl, luckily debug.hose.cam also makes that easy :p (ignore that it says it failed to issue a request crawl, CORS is fickle).
