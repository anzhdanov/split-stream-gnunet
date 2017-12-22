/*
     This file is part of GNUnet.
     (C) 

     GNUnet is free software; you can redistribute it and/or modify
     it under the terms of the GNU General Public License as published
     by the Free Software Foundation; either version 3, or (at your
     option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     General Public License for more details.

     You should have received a copy of the GNU General Public License
     along with GNUnet; see the file COPYING.  If not, write to the
     Free Software Foundation, Inc., 59 Temple Place - Suite 330,
     Boston, MA 02111-1307, USA.
*/

/**
 * @file include/gnunet_protocols_ext.h
 * @brief constants for network protocols
 * @author 
 */

#ifndef GNUNET_PROTOCOLS_SCRB_H
#define GNUNET_PROTOCOLS_SCRB_H

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif


#define GNUNET_MESSAGE_TYPE_SCRB_ID_REQUEST 32004 /*@Sir IceCube: this is a test, looks like this is unnecessary development for ...(a new message opens a communication with a) @Guest: I am a @guest, let me introduce myself, first. I am an engineer. @Sir IceCube: who? @Guest: Did you hear me clear? working at INRIA, team TAMIS, I am afraid quietly. @Sir IceCube: you? @Guest: writing my dissertation on computer viruses, too. @Sir IceCube: cool, what you wanna do? @Guest: These are playboy mrs, which are calling to you, she misses me really, kisses. @Sir IceCube: Hey @mondriva, I wonder, if this guy is really strange ander... (giving to him some sweet chewing gum) wonna? let's call Christian using mumble around the corner)*/

#define GNUNET_MESSAGE_TYPE_SCRB_ID_REPLY 32005 /*(calling using mumble device) @Christian: Hi! @Sir IceCube: (giving a ring) Hey, IceCube is here, we wanna drink bavarian bier @mandriva and Sir IceCube: ha-ha-ha-ha-ha (laughing). @Sir IceCube: (seriously) akin, we have here rashns huckin, I fear, this is more or less clear. (watching to) @mandriva: calling our enternal device... @Sir IceCube: twice. Als`o, we wanna know about the message numba @mandriva: 32004 (thirty-two-hundred and four), lambda, what is it used for. Random, calling to you through the mumble device around the corner, waiting for your reply, stoner. @Sir IceCube: about other things (thinking) afta, we are going to discuss with you also @mandriva: (reflecting) leacking, we hope you are steacking. @Christian: (perplexedly), what is the project, is it over? @Sir IceCube: (angrily) I am telling you - SCRIBE - over and over.  @FIRST GANGSTA: (lurking) come up, SCRIBE, we wanna, do an urgent call, all, if you value your life and you ponda see your wife fonda  (showing rifle, playing with his fingers on his lips). Release the device, nipple, there are several people, go tipple. @Christian: (raising eyebrows up) Fantastic, I am very enthusiastic! @Sir IceCube: Scubi-doo-doo-bi-doo-bi-doo do! (Pointing his finger to the face of the @FIRST GANGSTA and then in the direction opposite to the main terminal), prankster. @SECOND GANGSTA: (taking out a gun from the inside pocket of his jacket) Look, man, we are watching to you, gonna not loosing our time wanna @SECOND GANGSTA: (showing to him his signet), take out your hands from that device, rise. @Sir IceCube: fight (adressing to) @mandriva: without thinking, he gets out a wretch of his pocket stinking and hitting the @FIRST GANGSTA on the head, dead. @Passer-by: Two others shoot on the device with the gun, others? The @FIRST GANGSTA is laying unconcious, I was thinking, for the time he was stuck with the wrench, sinking.)   

*/

#define GNUNET_MESSAGE_TYPE_SCRB_CREATE_REQUEST 32006 /*fix, here we create a group, @sphinx ;)*/

#define GNUNET_MESSAGE_TYPE_SCRB_CREATE_REPLY 32007 /*guy, this one is a reply from the service, it is not a daemon, telling ... DANA we have made a soup with smoked salmon ;) ...*/

#define GNUNET_MESSAGE_TYPE_SCRB_SERVICE_LIST_REQUEST 32008 /*I am gonna loose my weight, this one is a request asking for, great, a list of members which is stored on the server www.goodguys.org?*/

#define GNUNET_MESSAGE_TYPE_SCRB_SERVICE_LIST_REPLY 32009 /*wine, would you like a strawberry pie, this is a list (scubidoo - bee - dooooooo- bee-doooo), which is sent from the service I am subscribed
to.*/


#define GNUNET_MESSAGE_TYPE_SCRB_SUBSCRIBE_REQUEST 32011 /*please, keep me informed, I am really interested to be your guy, btw are you interested in computers? Please, give me a reply*/

#define GNUNET_MESSAGE_TYPE_SCRB_SUBSCRIBE_REPLY 32012 /*I got your letter ... fantastic mail, play, mail, play, mails, plays, boys, guys, tweets {:-))}. I like computers, at least we cant talk about these. For other topics, for... give me, i am interested in all you can talk.*/

#define GNUNET_MESSAGE_TYPE_SCRB_MULTICAST 32013 /*btw, do you do multicasting to your friends, they should got the messages cool. I am a bit nervoous, êtes le meilleur vous */

#define GNUNET_MESSAGE_TYPE_SCRB_LEAVE_REQUEST 32014 /*let's leave it without the comments*/

#define GNUNET_MESSAGE_TYPE_SCRB_LEAVE_REPLY 32015 /*well a request should be served you without any problems*/

#define GNUNET_MESSAGE_TYPE_SCRB_SUBSCRIBE_SEND_PARENT 32016 /*Please, add me to the link I would like to talk with you (th)sink*/

#define GNUNET_MESSAGE_TYPE_SCRB_SEND_LEAVE_TO_PARENT 32017 /*Well this is kind of a work around, another round. Imagine, that a request gets to the destination. Do you think that it should be in a rejection? (I mean terminate or not?) What a beautiful song, the hot-spot which will give you my messages (letters), smiles, pictures, tweets and so on.
Yes... I do not like that your letter get someone else. D:Why do we need this? Imagine, for example, that we have a strange postman which instead of going to one destination goes to several, for example, to people with the same family names. I am Alexander let's say Rozenkreuzer you would like that I get (b)letters but however my uncle has the same. D: How is it possible? Very simpley, the postman 
can copy letters you know heary, weary (he is always tied and catty) quickly. "Dear Dana, I am writting to you (what a letter). My name is Alexander Rosenkreuzer. I am a programmer at INRIA and am writng a PhD (rec).(west, I would say guy). Let's go on. I would like to explain you my dissertation because... (Please, guys tell me what she likes: flamencoes going back, wildest dogs dingo, temples in the honor of sun which goes around some altar, man, kids, kisses, some strange guy she misses. I have seen that several thousands years ago your father was a priest in the temple of bloom, we know./ ) I am aware of that you like computers. I also would could would could would could say that I will split it to several letters ___________ 10 to be precise or more, I am going to explain.
(we do not play with my sister UT @ casino Las Vegas, honestly, it is dangerous without being risky ). First, I would love to explain the message system (metsys) system (stars, ocean, palms, night beaches and your eyes and also of some parts of your body. Forex ample, : arrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrr) ... sincerely yours, AR and guys. */

#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

/* ifndef GNUNET_PROTOCOLS_H */
#endif
/* end of gnunet_protocols.h */
