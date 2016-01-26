#ifndef __DASH_H__
#define __DASH_H__

static const char dash_mpd_header[] =
"<?xml version=\"1.0\"?>\n"
"<MPD\n"
"    xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\"\n"
"    xmlns=\"urn:mpeg:dash:schema:mpd:2011\"\n"
"    xsi:schemaLocation=\"urn:mpeg:dash:schema:mpd:2011 http://standards.iso.org/ittf/PubliclyAvailableStandards/MPEG-DASH_schema_files/DASH-MPD.xsd\"\n"
"    type=\"static\"\n"
"    mediaPresentationDuration=\"PT%i.%03iS\"\n"
"    minBufferTime=\"PT%iS\"\n"
"    profiles=\"urn:mpeg:dash:profile:isoff-main:2011\">\n"
"  <Period>\n";
static const char dash_mpd_adapt_video[] =
"    <AdaptationSet\n"
"        id=\"%i\"\n"
"        maxWidth=\"%uD\"\n"
"        maxHeight=\"%uD\"\n"
"        maxFrameRate=\"%i/%i\">\n";
static const char dash_mpd_adapt_audio[] =
"    <AdaptationSet\n"
"        id=\"%i\"\n"
"        segmentAlignment=\"true\">\n"
"      <AudioChannelConfiguration\n"
"          schemeIdUri=\"urn:mpeg:dash:23003:3:audio_channel_configuration:2011\"\n"
"          value=\"%uD\"/>\n";
static const char dash_mpd_segm[] =
"      <SegmentTemplate\n"
"          timescale=\"1000\"\n"
"          media=\"%Vseg-$Number$-$RepresentationID$.m4s\"\n"
"          initialization=\"%Vinit-$RepresentationID$.mp4\"\n"
"          startNumber=\"1\">\n"
"        <SegmentTimeline>\n";
static const char dash_mpd_tl_r[] = "          <S d=\"%i\" r=\"%i\"/>\n";
static const char dash_mpd_tl[]   = "          <S d=\"%i\"/>\n";
static const char dash_mpd_repr_video[] =
"        </SegmentTimeline>\n"
"      </SegmentTemplate>\n"
"      <Representation\n"
"          id=\"%i\"\n"
"          mimeType=\"video/mp4\"\n"
"          codecs=\"avc1.%02uxD%02uxD%02uxD\"\n"
"          width=\"%uD\"\n"
"          height=\"%uD\"\n"
"          frameRate=\"%uL/%uL\"\n"
"          bandwidth=\"%i\"/>\n"
"    </AdaptationSet>\n";
static const char dash_mpd_repr_audio[] =
"        </SegmentTimeline>\n"
"      </SegmentTemplate>\n"
"      <Representation\n"
"          id=\"%i\"\n"
"          mimeType=\"audio/mp4\"\n"
"          codecs=\"mp4a.40.%uD\"\n"
"          audioSamplingRate=\"%uD\"\n"
"          startWithSAP=\"1\"\n"
"          bandwidth=\"%uD\"/>\n"
"    </AdaptationSet>\n";
static u_char dash_mpd_footer[] = "  </Period>\n</MPD>\n";

#endif
