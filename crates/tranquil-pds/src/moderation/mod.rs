/*
 * CONTENT WARNING
 *
 * This file contains explicit slurs and hateful language. We're sorry you have to see them.
 *
 * These words exist here for one reason: to ensure our moderation system correctly blocks them.
 * We can't verify the filter catches the n-word without testing against the actual word.
 * Euphemisms wouldn't prove the protection works.
 *
 * If reading this file has caused you distress, please know:
 * - you are valued and welcome in this community
 * - these words do not reflect the views of this project or its contributors
 * - we maintain this code precisely because we believe everyone deserves an experience on the web that is free from this kinda language
*/

use regex::Regex;
use std::sync::OnceLock;

static SLUR_REGEXES: OnceLock<Vec<Regex>> = OnceLock::new();
static EXTRA_BANNED_WORDS: OnceLock<Vec<String>> = OnceLock::new();

fn get_slur_regexes() -> &'static Vec<Regex> {
    SLUR_REGEXES.get_or_init(|| {
        vec![
            Regex::new(r"\b[cĆćĈĉČčĊċÇçḈḉȻȼꞒꞓꟄꞔƇƈɕ][hĤĥȞȟḦḧḢḣḨḩḤḥḪḫH̱ẖĦħⱧⱨꞪɦꞕΗНн][iÍíi̇́Ììi̇̀ĬĭÎîǏǐÏïḮḯĨĩi̇̃ĮįĮ́į̇́Į̃į̇̃ĪīĪ̀ī̀ỈỉȈȉI̋i̋ȊȋỊịꞼꞽḬḭƗɨᶖİiIıＩｉ1lĺľļḷḹl̃ḽḻłŀƚꝉⱡɫɬꞎꬷꬸꬹᶅɭȴＬｌ][nŃńǸǹŇňÑñṄṅŅņṆṇṊṋṈṉN̈n̈ƝɲŊŋꞐꞑꞤꞥᵰᶇɳȵꬻꬼИиПпＮｎ][kḰḱǨǩĶķḲḳḴḵƘƙⱩⱪᶄꝀꝁꝂꝃꝄꝅꞢꞣ][sŚśṤṥŜŝŠšṦṧṠṡŞşṢṣṨṩȘșS̩s̩ꞨꞩⱾȿꟅʂᶊᵴ]?\b").unwrap(),
            Regex::new(r"\b[cĆćĈĉČčĊċÇçḈḉȻȼꞒꞓꟄꞔƇƈɕ][ÓóÒòŎŏÔôỐốỒồỖỗỔổǑǒÖöȪȫŐőÕõṌṍṎṏȬȭȮȯO͘o͘ȰȱØøǾǿǪǫǬǭŌōṒṓṐṑỎỏȌȍȎȏƠơỚớỜờỠỡỞởỢợỌọỘộO̩o̩Ò̩ò̩Ó̩ó̩ƟɵꝊꝋꝌꝍⱺＯｏ0]{2}[nŃńǸǹŇňÑñṄṅŅņṆṇṊṋṈṉN̈n̈ƝɲŊŋꞐꞑꞤꞥᵰᶇɳȵꬻꬼИиПпＮｎ][sŚśṤṥŜŝŠšṦṧṠṡŞşṢṣṨṩȘșS̩s̩ꞨꞩⱾȿꟅʂᶊᵴ]?\b").unwrap(),
            Regex::new(r"\b[fḞḟƑƒꞘꞙᵮᶂ][aÁáÀàĂăẮắẰằẴẵẲẳÂâẤấẦầẪẫẨẩǍǎÅåǺǻÄäǞǟÃãȦȧǠǡĄąĄ́ą́Ą̃ą̃ĀāĀ̀ā̀ẢảȀȁA̋a̋ȂȃẠạẶặẬậḀḁȺⱥꞺꞻᶏẚＡａ@4][gǴǵĞğĜĝǦǧĠġG̃g̃ĢģḠḡǤǥꞠꞡƓɠᶃꬶＧｇ]{1,2}([ÓóÒòŎŏÔôỐốỒồỖỗỔổǑǒÖöȪȫŐőÕõṌṍṎṏȬȭȮȯO͘o͘ȰȱØøǾǿǪǫǬǭŌōṒṓṐṑỎỏȌȍȎȏƠơỚớỜờỠỡỞởỢợỌọỘộO̩o̩Ò̩ò̩Ó̩ó̩ƟɵꝊꝋꝌꝍⱺＯｏ0e3ЄєЕеÉéÈèĔĕÊêẾếỀềỄễỂểÊ̄ê̄Ê̌ê̌ĚěËëẼẽĖėĖ́ė́Ė̃ė̃ȨȩḜḝĘęĘ́ę́Ę̃ę̃ĒēḖḗḔḕẺẻȄȅE̋e̋ȆȇẸẹỆệḘḙḚḛɆɇE̩e̩È̩è̩É̩é̩ᶒⱸꬴꬳＥｅiÍíi̇́Ììi̇̀ĬĭÎîǏǐÏïḮḯĨĩi̇̃ĮįĮ́į̇́Į̃į̇̃ĪīĪ̀ī̀ỈỉȈȉI̋i̋ȊȋỊịꞼꞽḬḭƗɨᶖİiIıＩｉ1lĺľļḷḹl̃ḽḻłŀƚꝉⱡɫɬꞎꬷꬸꬹᶅɭȴＬｌ][tŤťṪṫŢţṬṭȚțṰṱṮṯŦŧȾⱦƬƭƮʈT̈ẗᵵƫȶ]{1,2}([rŔŕŘřṘṙŖŗȐȑȒȓṚṛṜṝṞṟR̃r̃ɌɍꞦꞧⱤɽᵲᶉꭉ][yÝýỲỳŶŷY̊ẙŸÿỸỹẎẏȲȳỶỷỴỵɎɏƳƴỾỿ]|[rŔŕŘřṘṙŖŗȐȑȒȓṚṛṜṝṞṟR̃r̃ɌɍꞦꞧⱤɽᵲᶉꭉ][iÍíi̇́Ììi̇̀ĬĭÎîǏǐÏïḮḯĨĩi̇̃ĮįĮ́į̇́Į̃į̇̃ĪīĪ̀ī̀ỈỉȈȉI̋i̋ȊȋỊịꞼꞽḬḭƗɨᶖİiIıＩｉ1lĺľļḷḹl̃ḽḻłŀƚꝉⱡɫɬꞎꬷꬸꬹᶅɭȴＬｌ][e3ЄєЕеÉéÈèĔĕÊêẾếỀềỄễỂểÊ̄ê̄Ê̌ê̌ĚěËëẼẽĖėĖ́ė́Ė̃ė̃ȨȩḜḝĘęĘ́ę́Ę̃ę̃ĒēḖḗḔḕẺẻȄȅE̋e̋ȆȇẸẹỆệḘḙḚḛɆɇE̩e̩È̩è̩É̩é̩ᶒⱸꬴꬳＥｅ])?)?[sŚśṤṥŜŝŠšṦṧṠṡŞşṢṣṨṩȘșS̩s̩ꞨꞩⱾȿꟅʂᶊᵴ]?\b").unwrap(),
            Regex::new(r"\b[kḰḱǨǩĶķḲḳḴḵƘƙⱩⱪᶄꝀꝁꝂꝃꝄꝅꞢꞣ][iÍíi̇́Ììi̇̀ĬĭÎîǏǐÏïḮḯĨĩi̇̃ĮįĮ́į̇́Į̃į̇̃ĪīĪ̀ī̀ỈỉȈȉI̋i̋ȊȋỊịꞼꞽḬḭƗɨᶖİiIıＩｉ1lĺľļḷḹl̃ḽḻłŀƚꝉⱡɫɬꞎꬷꬸꬹᶅɭȴＬｌyÝýỲỳŶŷY̊ẙŸÿỸỹẎẏȲȳỶỷỴỵɎɏƳƴỾỿ][kḰḱǨǩĶķḲḳḴḵƘƙⱩⱪᶄꝀꝁꝂꝃꝄꝅꞢꞣ][e3ЄєЕеÉéÈèĔĕÊêẾếỀềỄễỂểÊ̄ê̄Ê̌ê̌ĚěËëẼẽĖėĖ́ė́Ė̃ė̃ȨȩḜḝĘęĘ́ę́Ę̃ę̃ĒēḖḗḔḕẺẻȄȅE̋e̋ȆȇẸẹỆệḘḙḚḛɆɇE̩e̩È̩è̩É̩é̩ᶒⱸꬴꬳＥｅ]([rŔŕŘřṘṙŖŗȐȑȒȓṚṛṜṝṞṟR̃r̃ɌɍꞦꞧⱤɽᵲᶉꭉ][yÝýỲỳŶŷY̊ẙŸÿỸỹẎẏȲȳỶỷỴỵɎɏƳƴỾỿ]|[rŔŕŘřṘṙŖŗȐȑȒȓṚṛṜṝṞṟR̃r̃ɌɍꞦꞧⱤɽᵲᶉꭉ][iÍíi̇́Ììi̇̀ĬĭÎîǏǐÏïḮḯĨĩi̇̃ĮįĮ́į̇́Į̃į̇̃ĪīĪ̀ī̀ỈỉȈȉI̋i̋ȊȋỊịꞼꞽḬḭƗɨᶖİiIıＩｉ1lĺľļḷḹl̃ḽḻłŀƚꝉⱡɫɬꞎꬷꬸꬹᶅɭȴＬｌ][e3ЄєЕеÉéÈèĔĕÊêẾếỀềỄễỂểÊ̄ê̄Ê̌ê̌ĚěËëẼẽĖėĖ́ė́Ė̃ė̃ȨȩḜḝĘęĘ́ę́Ę̃ę̃ĒēḖḗḔḕẺẻȄȅE̋e̋ȆȇẸẹỆệḘḙḚḛɆɇE̩e̩È̩è̩É̩é̩ᶒⱸꬴꬳＥｅ])?[sŚśṤṥŜŝŠšṦṧṠṡŞşṢṣṨṩȘșS̩s̩ꞨꞩⱾȿꟅʂᶊᵴ]*\b").unwrap(),
            Regex::new(r"\b[nŃńǸǹŇňÑñṄṅŅņṆṇṊṋṈṉN̈n̈ƝɲŊŋꞐꞑꞤꞥᵰᶇɳȵꬻꬼИиПпＮｎ][iÍíi̇́Ììi̇̀ĬĭÎîǏǐÏïḮḯĨĩi̇̃ĮįĮ́į̇́Į̃į̇̃ĪīĪ̀ī̀ỈỉȈȉI̋i̋ȊȋỊịꞼꞽḬḭƗɨᶖİiIıＩｉ1lĺľļḷḹl̃ḽḻłŀƚꝉⱡɫɬꞎꬷꬸꬹᶅɭȴＬｌoÓóÒòŎŏÔôỐốỒồỖỗỔổǑǒÖöȪȫŐőÕõṌṍṎṏȬȭȮȯO͘o͘ȰȱØøǾǿǪǫǬǭŌōṒṓṐṑỎỏȌȍȎȏƠơỚớỜờỠỡỞởỢợỌọỘộO̩o̩Ò̩ò̩Ó̩ó̩ƟɵꝊꝋꝌꝍⱺＯｏІіa4ÁáÀàĂăẮắẰằẴẵẲẳÂâẤấẦầẪẫẨẩǍǎÅåǺǻÄäǞǟÃãȦȧǠǡĄąĄ́ą́Ą̃ą̃ĀāĀ̀ā̀ẢảȀȁA̋a̋ȂȃẠạẶặẬậḀḁȺⱥꞺꞻᶏẚＡａ][gǴǵĞğĜĝǦǧĠġG̃g̃ĢģḠḡǤǥꞠꞡƓɠᶃꬶＧｇqꝖꝗꝘꝙɋʠ]{2}(l[e3ЄєЕеÉéÈèĔĕÊêẾếỀềỄễỂểÊ̄ê̄Ê̌ê̌ĚěËëẼẽĖėĖ́ė́Ė̃ė̃ȨȩḜḝĘęĘ́ę́Ę̃ę̃ĒēḖḗḔḕẺẻȄȅE̋e̋ȆȇẸẹỆệḘḙḚḛɆɇE̩e̩È̩è̩É̩é̩ᶒⱸꬴꬳＥｅ]t|[e3ЄєЕеÉéÈèĔĕÊêẾếỀềỄễỂểÊ̄ê̄Ê̌ê̌ĚěËëẼẽĖėĖ́ė́Ė̃ė̃ȨȩḜḝĘęĘ́ę́Ę̃ę̃ĒēḖḗḔḕẺẻȄȅE̋e̋ȆȇẸẹỆệḘḙḚḛɆɇE̩e̩È̩è̩É̩é̩ᶒⱸꬴꬳＥｅaÁáÀàĂăẮắẰằẴẵẲẳÂâẤấẦầẪẫẨẩǍǎÅåǺǻÄäǞǟÃãȦȧǠǡĄąĄ́ą́Ą̃ą̃ĀāĀ̀ā̀ẢảȀȁA̋a̋ȂȃẠạẶặẬậḀḁȺⱥꞺꞻᶏẚＡａ][rŔŕŘřṘṙŖŗȐȑȒȓṚṛṜṝṞṟR̃r̃ɌɍꞦꞧⱤɽᵲᶉꭉ]?|n[ÓóÒòŎŏÔôỐốỒồỖỗỔổǑǒÖöȪȫŐőÕõṌṍṎṏȬȭȮȯO͘o͘ȰȱØøǾǿǪǫǬǭŌōṒṓṐṑỎỏȌȍȎȏƠơỚớỜờỠỡỞởỢợỌọỘộO̩o̩Ò̩ò̩Ó̩ó̩ƟɵꝊꝋꝌꝍⱺＯｏ0][gǴǵĞğĜĝǦǧĠġG̃g̃ĢģḠḡǤǥꞠꞡƓɠᶃꬶＧｇqꝖꝗꝘꝙɋʠ]|[a4ÁáÀàĂăẮắẰằẴẵẲẳÂâẤấẦầẪẫẨẩǍǎÅåǺǻÄäǞǟÃãȦȧǠǡĄąĄ́ą́Ą̃ą̃ĀāĀ̀ā̀ẢảȀȁA̋a̋ȂȃẠạẶặẬậḀḁȺⱥꞺꞻᶏẚＡａ]?)?[sŚśṤṥŜŝŠšṦṧṠṡŞşṢṣṨṩȘșS̩s̩ꞨꞩⱾȿꟅʂᶊᵴ]?\b").unwrap(),
            Regex::new(r"[nŃńǸǹŇňÑñṄṅŅņṆṇṊṋṈṉN̈n̈ƝɲŊŋꞐꞑꞤꞥᵰᶇɳȵꬻꬼИиПпＮｎ][iÍíi̇́Ììi̇̀ĬĭÎîǏǐÏïḮḯĨĩi̇̃ĮįĮ́į̇́Į̃į̇̃ĪīĪ̀ī̀ỈỉȈȉI̋i̋ȊȋỊịꞼꞽḬḭƗɨᶖİiIıＩｉ1lĺľļḷḹl̃ḽḻłŀƚꝉⱡɫɬꞎꬷꬸꬹᶅɭȴＬｌoÓóÒòŎŏÔôỐốỒồỖỗỔổǑǒÖöȪȫŐőÕõṌṍṎṏȬȭȮȯO͘o͘ȰȱØøǾǿǪǫǬǭŌōṒṓṐṑỎỏȌȍȎȏƠơỚớỜờỠỡỞởỢợỌọỘộO̩o̩Ò̩ò̩Ó̩ó̩ƟɵꝊꝋꝌꝍⱺＯｏІіa4ÁáÀàĂăẮắẰằẴẵẲẳÂâẤấẦầẪẫẨẩǍǎÅåǺǻÄäǞǟÃãȦȧǠǡĄąĄ́ą́Ą̃ą̃ĀāĀ̀ā̀ẢảȀȁA̋a̋ȂȃẠạẶặẬậḀḁȺⱥꞺꞻᶏẚＡａ][gǴǵĞğĜĝǦǧĠġG̃g̃ĢģḠḡǤǥꞠꞡƓɠᶃꬶＧｇqꝖꝗꝘꝙɋʠ]{2}(l[e3ЄєЕеÉéÈèĔĕÊêẾếỀềỄễỂểÊ̄ê̄Ê̌ê̌ĚěËëẼẽĖėĖ́ė́Ė̃ė̃ȨȩḜḝĘęĘ́ę́Ę̃ę̃ĒēḖḗḔḕẺẻȄȅE̋e̋ȆȇẸẹỆệḘḙḚḛɆɇE̩e̩È̩è̩É̩é̩ᶒⱸꬴꬳＥｅ]t|[e3ЄєЕеÉéÈèĔĕÊêẾếỀềỄễỂểÊ̄ê̄Ê̌ê̌ĚěËëẼẽĖėĖ́ė́Ė̃ė̃ȨȩḜḝĘęĘ́ę́Ę̃ę̃ĒēḖḗḔḕẺẻȄȅE̋e̋ȆȇẸẹỆệḘḙḚḛɆɇE̩e̩È̩è̩É̩é̩ᶒⱸꬴꬳＥｅ][rŔŕŘřṘṙŖŗȐȑȒȓṚṛṜṝṞṟR̃r̃ɌɍꞦꞧⱤɽᵲᶉꭉ])[sŚśṤṥŜŝŠšṦṧṠṡŞşṢṣṨṩȘșS̩s̩ꞨꞩⱾȿꟅʂᶊᵴ]?").unwrap(),
            Regex::new(r"\b[tŤťṪṫŢţṬṭȚțṰṱṮṯŦŧȾⱦƬƭƮʈT̈ẗᵵƫȶ][rŔŕŘřṘṙŖŗȐȑȒȓṚṛṜṝṞṟR̃r̃ɌɍꞦꞧⱤɽᵲᶉꭉ][aÁáÀàĂăẮắẰằẴẵẲẳÂâẤấẦầẪẫẨẩǍǎÅåǺǻÄäǞǟÃãȦȧǠǡĄąĄ́ą́Ą̃ą̃ĀāĀ̀ā̀ẢảȀȁA̋a̋ȂȃẠạẶặẬậḀḁȺⱥꞺꞻᶏẚＡａ4]+[nŃńǸǹŇňÑñṄṅŅņṆṇṊṋṈṉN̈n̈ƝɲŊŋꞐꞑꞤꞥᵰᶇɳȵꬻꬼИиПпＮｎ]{1,2}([iÍíi̇́Ììi̇̀ĬĭÎîǏǐÏïḮḯĨĩi̇̃ĮįĮ́į̇́Į̃į̇̃ĪīĪ̀ī̀ỈỉȈȉI̋i̋ȊȋỊịꞼꞽḬḭƗɨᶖİiIıＩｉ1lĺľļḷḹl̃ḽḻłŀƚꝉⱡɫɬꞎꬷꬸꬹᶅɭȴＬｌ][e3ЄєЕеÉéÈèĔĕÊêẾếỀềỄễỂểÊ̄ê̄Ê̌ê̌ĚěËëẼẽĖėĖ́ė́Ė̃ė̃ȨȩḜḝĘęĘ́ę́Ę̃ę̃ĒēḖḗḔḕẺẻȄȅE̋e̋ȆȇẸẹỆệḘḙḚḛɆɇE̩e̩È̩è̩É̩é̩ᶒⱸꬴꬳＥｅ]|[yÝýỲỳŶŷY̊ẙŸÿỸỹẎẏȲȳỶỷỴỵɎɏƳƴỾỿ]|[e3ЄєЕеÉéÈèĔĕÊêẾếỀềỄễỂểÊ̄ê̄Ê̌ê̌ĚěËëẼẽĖėĖ́ė́Ė̃ė̃ȨȩḜḝĘęĘ́ę́Ę̃ę̃ĒēḖḗḔḕẺẻȄȅE̋e̋ȆȇẸẹỆệḘḙḚḛɆɇE̩e̩È̩è̩É̩é̩ᶒⱸꬴꬳＥｅ][rŔŕŘřṘṙŖŗȐȑȒȓṚṛṜṝṞṟR̃r̃ɌɍꞦꞧⱤɽᵲᶉꭉ])[sŚśṤṥŜŝŠšṦṧṠṡŞşṢṣṨṩȘșS̩s̩ꞨꞩⱾȿꟅʂᶊᵴ]?\b").unwrap(),
        ]
    })
}

fn get_extra_banned_words() -> &'static Vec<String> {
    EXTRA_BANNED_WORDS.get_or_init(|| tranquil_config::get().server.banned_word_list())
}

fn strip_trailing_digits(s: &str) -> &str {
    s.trim_end_matches(|c: char| c.is_ascii_digit())
}

fn normalize_leetspeak(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            '4' | '@' => 'a',
            '3' => 'e',
            '1' | '!' | '|' => 'i',
            '0' => 'o',
            '5' | '$' => 's',
            '7' => 't',
            '8' => 'b',
            '9' => 'g',
            _ => c,
        })
        .collect()
}

pub fn has_explicit_slur(text: &str) -> bool {
    has_explicit_slur_with_extra_words(text, get_extra_banned_words())
}

fn has_explicit_slur_with_extra_words(text: &str, extra_words: &[String]) -> bool {
    let text_lower = text.to_lowercase();
    let normalized = text_lower.replace(['.', '-', '_'], "");
    let stripped = strip_trailing_digits(&text_lower);
    let normalized_stripped = strip_trailing_digits(&normalized);

    let regexes = get_slur_regexes();
    if regexes.iter().any(|r| {
        r.is_match(&text_lower)
            || r.is_match(&normalized)
            || r.is_match(stripped)
            || r.is_match(normalized_stripped)
    }) {
        return true;
    }

    if !extra_words.is_empty() {
        let leet_normalized = normalize_leetspeak(&normalized);
        let leet_stripped = normalize_leetspeak(strip_trailing_digits(&leet_normalized));
        if extra_words.iter().any(|w| {
            text_lower.contains(w)
                || normalized.contains(w)
                || stripped.contains(w)
                || normalized_stripped.contains(w)
                || leet_normalized.contains(w)
                || leet_stripped.contains(w)
        }) {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;

    fn d(b64: &str) -> String {
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(b64)
            .unwrap();
        String::from_utf8(bytes).unwrap()
    }

    #[test]
    fn test_chink_pattern() {
        assert!(has_explicit_slur(&d("Y2hpbms=")));
        assert!(has_explicit_slur(&d("Y2hpbmtz")));
        assert!(has_explicit_slur(&d("Q0hJTks=")));
        assert!(has_explicit_slur(&d("Q2hpbmtz")));
    }

    #[test]
    fn test_coon_pattern() {
        assert!(has_explicit_slur(&d("Y29vbg==")));
        assert!(has_explicit_slur(&d("Y29vbnM=")));
        assert!(has_explicit_slur(&d("Q09PTg==")));
    }

    #[test]
    fn test_fag_pattern() {
        assert!(has_explicit_slur(&d("ZmFn")));
        assert!(has_explicit_slur(&d("ZmFncw==")));
        assert!(has_explicit_slur(&d("ZmFnZ290")));
        assert!(has_explicit_slur(&d("ZmFnZ290cw==")));
        assert!(has_explicit_slur(&d("ZmFnZ290cnk=")));
    }

    #[test]
    fn test_kike_pattern() {
        assert!(has_explicit_slur(&d("a2lrZQ==")));
        assert!(has_explicit_slur(&d("a2lrZXM=")));
        assert!(has_explicit_slur(&d("S0lLRQ==")));
        assert!(has_explicit_slur(&d("a2lrZXJ5")));
    }

    #[test]
    fn test_nigger_pattern() {
        assert!(has_explicit_slur(&d("bmlnZ2Vy")));
        assert!(has_explicit_slur(&d("bmlnZ2Vycw==")));
        assert!(has_explicit_slur(&d("TklHR0VS")));
        assert!(has_explicit_slur(&d("bmlnZ2E=")));
        assert!(has_explicit_slur(&d("bmlnZ2Fz")));
    }

    #[test]
    fn test_tranny_pattern() {
        assert!(has_explicit_slur(&d("dHJhbm55")));
        assert!(has_explicit_slur(&d("dHJhbm5pZXM=")));
        assert!(has_explicit_slur(&d("VFJBTk5Z")));
    }

    #[test]
    fn test_normalization_bypass() {
        assert!(has_explicit_slur(&d("bi5pLmcuZy5lLnI=")));
        assert!(has_explicit_slur(&d("bi1pLWctZy1lLXI=")));
        assert!(has_explicit_slur(&d("bl9pX2dfZ19lX3I=")));
        assert!(has_explicit_slur(&d("Zi5hLmc=")));
        assert!(has_explicit_slur(&d("Zi1hLWc=")));
        assert!(has_explicit_slur(&d("Yy5oLmkubi5r")));
        assert!(has_explicit_slur(&d("a19pX2tfZQ==")));
    }

    #[test]
    fn test_trailing_digits_bypass() {
        assert!(has_explicit_slur(&d("ZmFnZ290MTIz")));
        assert!(has_explicit_slur(&d("bmlnZ2VyNjk=")));
        assert!(has_explicit_slur(&d("Y2hpbms0MjA=")));
        assert!(has_explicit_slur(&d("ZmFnMQ==")));
        assert!(has_explicit_slur(&d("a2lrZTIwMjQ=")));
        assert!(has_explicit_slur(&d("bl9pX2dfZ19lX3IxMjM=")));
    }

    #[test]
    fn test_embedded_in_sentence() {
        assert!(has_explicit_slur(&d("eW91IGFyZSBhIGZhZ2dvdA==")));
        assert!(has_explicit_slur(&d("c3R1cGlkIG5pZ2dlcg==")));
        assert!(has_explicit_slur(&d("Z28gYXdheSBjaGluaw==")));
    }

    #[test]
    fn test_safe_words_not_matched() {
        assert!(!has_explicit_slur("hello"));
        assert!(!has_explicit_slur("world"));
        assert!(!has_explicit_slur("bluesky"));
        assert!(!has_explicit_slur("tranquil"));
        assert!(!has_explicit_slur("programmer"));
        assert!(!has_explicit_slur("trigger"));
        assert!(!has_explicit_slur("bigger"));
        assert!(!has_explicit_slur("digger"));
        assert!(!has_explicit_slur("figure"));
        assert!(!has_explicit_slur("configure"));
    }

    #[test]
    fn test_similar_but_safe_words() {
        assert!(!has_explicit_slur("niggardly"));
        assert!(!has_explicit_slur("raccoon"));
    }

    #[test]
    fn test_empty_and_whitespace() {
        assert!(!has_explicit_slur(""));
        assert!(!has_explicit_slur("   "));
        assert!(!has_explicit_slur("\t\n"));
    }

    #[test]
    fn test_case_insensitive() {
        assert!(has_explicit_slur(&d("TklHR0VS")));
        assert!(has_explicit_slur(&d("TmlnZ2Vy")));
        assert!(has_explicit_slur(&d("TmlHZ0Vy")));
        assert!(has_explicit_slur(&d("RkFHR09U")));
        assert!(has_explicit_slur(&d("RmFnZ290")));
    }

    #[test]
    fn test_leetspeak_bypass() {
        assert!(has_explicit_slur(&d("ZjRnZ290")));
        assert!(has_explicit_slur(&d("ZjRnZzB0")));
        assert!(has_explicit_slur(&d("bjFnZ2Vy")));
        assert!(has_explicit_slur(&d("bjFnZzNy")));
        assert!(has_explicit_slur(&d("azFrZQ==")));
        assert!(has_explicit_slur(&d("Y2gxbms=")));
        assert!(has_explicit_slur(&d("dHI0bm55")));
    }

    #[test]
    fn test_normalize_leetspeak() {
        assert_eq!(normalize_leetspeak("h3llo"), "hello");
        assert_eq!(normalize_leetspeak("w0rld"), "world");
        assert_eq!(normalize_leetspeak("t3$t"), "test");
        assert_eq!(normalize_leetspeak("b4dw0rd"), "badword");
        assert_eq!(normalize_leetspeak("l33t5p34k"), "leetspeak");
        assert_eq!(normalize_leetspeak("@ss"), "ass");
        assert_eq!(normalize_leetspeak("sh!t"), "shit");
        assert_eq!(normalize_leetspeak("normal"), "normal");
    }

    #[test]
    fn test_extra_banned_words() {
        let extra = vec!["badword".to_string(), "offensive".to_string()];

        assert!(has_explicit_slur_with_extra_words("badword", &extra));
        assert!(has_explicit_slur_with_extra_words("BADWORD", &extra));
        assert!(has_explicit_slur_with_extra_words("b.a.d.w.o.r.d", &extra));
        assert!(has_explicit_slur_with_extra_words("b-a-d-w-o-r-d", &extra));
        assert!(has_explicit_slur_with_extra_words("b_a_d_w_o_r_d", &extra));
        assert!(has_explicit_slur_with_extra_words("badword123", &extra));
        assert!(has_explicit_slur_with_extra_words("b4dw0rd", &extra));
        assert!(has_explicit_slur_with_extra_words("b4dw0rd789", &extra));
        assert!(has_explicit_slur_with_extra_words("b.4.d.w.0.r.d", &extra));
        assert!(has_explicit_slur_with_extra_words(
            "this contains badword here",
            &extra
        ));
        assert!(has_explicit_slur_with_extra_words("0ff3n$1v3", &extra));

        assert!(!has_explicit_slur_with_extra_words("goodword", &extra));
        assert!(!has_explicit_slur_with_extra_words("hello world", &extra));
    }
}
