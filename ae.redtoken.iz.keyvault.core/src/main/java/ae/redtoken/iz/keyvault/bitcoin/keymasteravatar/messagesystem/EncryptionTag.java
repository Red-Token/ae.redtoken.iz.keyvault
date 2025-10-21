package ae.redtoken.iz.keyvault.bitcoin.keymasteravatar.messagesystem;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import com.fasterxml.jackson.databind.JsonNode;
import lombok.*;
import nostr.base.PublicKey;
import nostr.base.annotation.Key;
import nostr.base.annotation.Tag;
import nostr.event.BaseTag;
import nostr.event.tag.PubKeyTag;

@Builder
@Data
@EqualsAndHashCode(callSuper = true)
@AllArgsConstructor
@Tag(code = "encryption", name = "encryptionType")
@JsonPropertyOrder({"type"})
@NoArgsConstructor
public class EncryptionTag extends BaseTag {
    @Key
    @JsonProperty("type")
    private NostrEncryptionType type;

    public static <T extends BaseTag> T deserialize(@NonNull JsonNode node) {
        if (node == null) {
            throw new NullPointerException("node is marked non-null but is null");
        } else {
            EncryptionTag tag = new EncryptionTag();
            JsonNode nodeEncryptionType = node.get(1);
            if (nodeEncryptionType != null) {
                tag.setType(NostrEncryptionType.valueOf(nodeEncryptionType.asText()));
            }

            return (T)tag;
        }
    }
}
