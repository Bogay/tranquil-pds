Hello! This is Lewis, oyster.cafe, writing the "I" pronouns! Time to write some in-depth guides on the experience of actually running this thing, hopefully with explanation of what we're even doing here and why, so let's start there.

If you think that our docs are missing some aspect of Tranquil PDS, please let us know, preferably as an issue right here on Tangled.

I will assume from here on out that you know what a [PDS](https://atproto.com/guides/glossary#pds-personal-data-server) is, and also that you read the main README.md at project root and like what you see regarding all our features.

# Tranquil & the world

A PDS is an extremely important aspect of atproto in general, dare I say the bedrock of the whole thing. Storing data reliably and giving it out at the right time is its bread and butter, and if it fails that even once then it breaks its contract with you.
The reference ("ref") PDS uses SQLite for its storage backend, and Tranquil opted to go with PostgreSQL initially (and we have an experimental embedded-db that we sorta made ourselves). We'd also like to implement a SQLite backend too - to that effect we have made a database trait with both postgres and our embedded db implementing the correct functions! All it takes to add a SQLite backend is implementing those same functions - hell wouldn't it be fun to have some fun storage backends too?
Each storage backend has its trade-offs - so at the heart of Tranquil we always want to give users choice and put them in the driving seat - why should we choose your storage backend for you if you have a hankering for MongoDB or something? Go ahead and implement the database functions, let's have it. If I sound sarcastic I'm sorry, I'm actually serious.

Which database should you choose? At time of writing the answer is most definitely postgres - if you choose our embedded db right now please don't complain if you have data loss, the one thing a PDS is not supposed to have - though if you do choose it we'd love the live user testing by fire.

With that fundamental storage choice out of the way (ie. 'we give you choice but please choose postgres for now', amazing logic Lewis) the other config options are more fleshed out and do in fact have valid dual-options. For example, blob storage -> do you want to KISS? Go with filesystem. Do you get free credits at a cloud company like a certain developer did when he wrote this option? Go with Object Storage.
Please browse the example.toml at project root for all of them, we promise that the important ones say as much, and the less-important ones have sane defaults.

Apart from your personal technological taste, dear PDS admin, what other things might you take into account when choosing your config? Here's something for you to chew on: Tranquil aims to never "default" to Bluesky in the same way the reference does. There's no "default AppView" to fall back to with requests, we don't encourage you to talk to Bluesky relays (though they're big, decent, and themselves not Bluesky-specific). This philosophy is either a blessing or an achilles heel for Tranquil depending on how you look at things. For example, I mentioned not defaulting to an AppView: atproto apps that assume that a PDS *does* default to an AppView will find out the hard way that if they don't specify a request header called `atproto-proxy`, Tranquil does not forward on a request to any fallback. Why should we?

> // 🦪 TODO: write an exhaustive list of problems using apps with Tranquil that are due to us trying better to follow spec

Therefore that's a caveat to Tranquil, **you accidentally or purposefully help the whole atproto ecosystem be better** by the trial of apps literally not working for you unless they're correct.

There's one aspect of Tranquil that doesn't work with regular apps which isn't necessarily a spec violation but our taste (we try to keep matters of taste to a minimum, and we're debating having this one configurable): mixing [transitional OAuth](https://atproto.com/specs/oauth#transitional-scopes) with properly scoped OAuth.
Why do we disallow mixing them? Because it defeats the purpose of the OAuth scopes if you tack on a "and everything else" scope at the end. We think apps should do better and just correctly choose the right scopes to their own apps.

> 🌺 Nel
>
> One way I've taken to quickly summerising the goal of Tranquil is:
> - Be right
> - Be good
> - Be fun
>
> "Be right" as in follow spec. The reference implementation has several instances of non-spec behaviour. Our aim is for Tranquil to have as little as possible of that. Every so often we are forced to do that to have any chance at Bluesky working but when there is a spec way to accomplished something that's the method Tranquil supports. This does cause issues like mentioned above but we feel it is worth it to set a community precedent that spec matters. Open protocols live and die by spec and whether or not it's followed.
> "Be good" as in be a good, useful, featureful, fast implementation. Tranquil is full of features that we felt have been missing from the PDSs scene. Things like passkeys, totp 2fa, more comms methods than email, SSO sign up and sign on but also more unique features like delegated accounts. We want to be something maximally useful to us and to you!
> "Be fun" as in be fun to make and use! This is a hobby project for both of us and we don't have plans for it to ever be more than that. Tranquil isn't a cooporate product, it's a community and personal project born out of a wish for something better. We're going to have fun with it, we hope you do too!
>
> All these three are also acompanied by a general "by the community, for the community" approach. We'd love to hear your ideas, wants and needs and get your contributions. Tranquil is for you just as much as it is for us! Anyways back to Lewis he's a clever guy.

Hopefully this has given you some insight into what drives us and what guides our hands when writing Tranquil. If we've stimulated your imagination on what a PDS could do better for you, for us, then please get involved! We need more hands and more voices.

# Deployment

You will notice in this folder that there are some install guides based on which average deployment method you enjoy. You will also notice that there's no simple "deploy raw binary" -> we would like to set up our CI to properly upload releases in our repo such that anyone can just pick the latest binary and run it on their server.

So now you have deployed your Tranquil PDS. Welcome!

When you first deploy, and you have invite codes required for your instance, you might ask yourself "ok so how do I make the first invite code?" -> it is there, in the server logs, waiting for you!

As an admin, there's a special page in the frontend where you can manage accounts. Right now it is quite barebones and honestly if it weren't for the option to delete accounts, we might simply recommend that you use [pds.ls](https://pds.ls).

> 🦪 Lewis
>
> We would like to write a client CLI for Tranquil and focus a lot of effort on that, including/especially for more fully-featured admin'ing.

# Account migration

So you want to migrate your account from a different PDS to Tranquil? The UI of Tranquil does show that we have an in-house migrator web UI. It's as good as most migrator apps out there today, apart from [pdsmoover.com](https://pdsmoover.com). Using PDSMoover will tell you that you must verify your account before continuing to the last step, that's not their bug but our design - instead of bothering with captchas, that's a layer of security we have chosen. If you simply verify your account via the email/discord/telegram/signal link your PDS sent, you can just continue in PDSMoover immediately.

> 🦪 Lewis
>
> To be honest, writing a migrator has shown us that there's a need to redo migration from first principles -> right now migration involves many load-bearing steps, almost any one of which leaves you somewhere gross in the middle if something messes up. Imagine if we could just package up all the important data in one go beforehand, and shift it all at once in a retryable way...

The good thing about migrations is that for most of the rickety process, the real identity of your account hasn't actually moved, it's most of the unimportant data copied over (ie. everything but switching over your keys to say "hey this account is hosted on this specific PDS instance and not any other one"). So if something goes wrong in our migrator or any other, feel free to dip into a bit of Tranquil PDS admin and delete out the half-formed account ~~fetus~~ (sorry).

One thing that **tends to not go smoothly in our own migrator** right now is **session token refresh** -> it's surprisingly hard for me to figure out how to best refresh an OAuth token for an account that's not even technically really created yet, and if you wait too long in the browser during the migration then sometimes it seems to just start erroring out because of a dead session token. This is a really bad UX! I will fix this in the near future unless someone else fixes it first. I have successfully been on the line with an oomf migrating who had this happen, and we actually forced a token refresh via the browser console - so there's that if you don't want to start again after deleting the half-made account.
